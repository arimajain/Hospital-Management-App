# app.py
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
)
import sqlite3, os, csv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from io import StringIO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hospital.db")

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_key"  # change for production

# -------- DB helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    # USERS
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','doctor','patient')),
      full_name TEXT, email TEXT, phone TEXT, is_active INTEGER DEFAULT 1
    );
    """)
    # DEPARTMENTS
    db.execute("""
    CREATE TABLE IF NOT EXISTS departments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT
    );
    """)
        # DOCTORS (experience column included)
    db.execute("""
    CREATE TABLE IF NOT EXISTS doctors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        department_id INTEGER,
        experience TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(department_id) REFERENCES departments(id)
    );
    """)
    # PATIENTS
    db.execute("""
    CREATE TABLE IF NOT EXISTS patients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      address TEXT, blood_group TEXT, emergency_contact TEXT, age INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    # APPOINTMENTS
    db.execute("""
    CREATE TABLE IF NOT EXISTS appointments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id INTEGER NOT NULL,
      doctor_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      end_time TEXT,
      status TEXT NOT NULL DEFAULT 'Booked' CHECK(status IN ('Booked','Completed','Cancelled')),
      created_at TEXT NOT NULL,
      FOREIGN KEY(patient_id) REFERENCES patients(id),
      FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    );
    """)
    # TREATMENTS
    db.execute("""
    CREATE TABLE IF NOT EXISTS treatments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      appointment_id INTEGER UNIQUE NOT NULL,
      diagnosis TEXT, prescription TEXT, notes TEXT,
      FOREIGN KEY(appointment_id) REFERENCES appointments(id)
    );
    """)
    # DOCTOR AVAILABILITY
    db.execute("""
    CREATE TABLE IF NOT EXISTS doctor_availability (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      doctor_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      is_booked INTEGER DEFAULT 0,
      booked_by INTEGER,
      booked_at TEXT,
      FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    );
    """)
    # RESCHEDULE REQUESTS
    db.execute("""
    CREATE TABLE IF NOT EXISTS reschedule_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      appointment_id INTEGER NOT NULL,
      patient_id INTEGER NOT NULL,
      requested_slot_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Approved','Rejected')),
      created_at TEXT NOT NULL,
      responded_at TEXT,
      responder_id INTEGER,
      FOREIGN KEY(appointment_id) REFERENCES appointments(id),
      FOREIGN KEY(patient_id) REFERENCES patients(id),
      FOREIGN KEY(requested_slot_id) REFERENCES doctor_availability(id)
    );
    """)
    # indices
    db.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_appointments_unique
    ON appointments(doctor_id, date, time);
    """)
    db.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_doctor_availability_unique
    ON doctor_availability(doctor_id, date, start_time, end_time);
    """)
    
    try:
        db.execute("ALTER TABLE patients ADD COLUMN age INTEGER")
    except sqlite3.OperationalError:
        pass 
        
    db.commit()
    
    # ensure default admin exists
    cur = db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1;")
    if cur.fetchone() is None:
        ph = generate_password_hash("admin123")
        db.execute("INSERT INTO users (username,password_hash,role,full_name,email) VALUES (?,?,?,?,?)",
                   ("admin", ph, "admin", "Default Admin", "admin@example.com"))
        db.commit()
        print("Created default admin: username='admin', password='admin123'")

# -------- Utilities ----------
def generate_time_slots():
    slots = []
    for h in range(9, 21):
        for m in range(0, 60, 5):
            slots.append(f"{h:02d}:{m:02d}")
    slots.append("21:00")
    return slots

def time_to_minutes(t):
    h, m = map(int, t.split(":"))
    return h * 60 + m

def is_within_bounds(t):
    return time_to_minutes("09:00") <= time_to_minutes(t) <= time_to_minutes("21:00")

def is_5min_multiple(t):
    try:
        return int(t.split(":")[1]) % 5 == 0
    except:
        return False

# -------- Auth decorator ----------
def login_required(role=None):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role is not None and session.get("role") != role:
                flash("Not authorized.", "danger")
                r = session.get("role")
                if r == "admin": return redirect(url_for("admin_dashboard"))
                if r == "doctor": return redirect(url_for("doctor_dashboard"))
                if r == "patient": return redirect(url_for("patient_dashboard"))
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# -------- Routes: Auth ----------
@app.route("/")
def index():
    if "user_id" in session:
        r = session.get("role")
        if r == "admin": return redirect(url_for("admin_dashboard"))
        if r == "doctor": return redirect(url_for("doctor_dashboard"))
        if r == "patient": return redirect(url_for("patient_dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username=? AND is_active=1", (u,))
        user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], p):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            flash("Logged in.", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register_patient():
    if request.method=="POST":
        username = request.form["username"].strip()
        full_name = request.form["full_name"].strip()
        email = request.form["email"].strip()
        phone = request.form["phone"].strip()
        password = request.form["password"]
        confirm = request.form["confirm"]
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register_patient.html")
        db = get_db()
        try:
            ph = generate_password_hash(password)
            cur = db.execute("INSERT INTO users (username,password_hash,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
                             (username, ph, "patient", full_name, email, phone))
            user_id = cur.lastrowid
            db.execute("INSERT INTO patients (user_id) VALUES (?)", (user_id,))
            db.commit()
            flash("Registered successfully. Login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username exists.", "danger")
    return render_template("register_patient.html")

# -------- Admin routes ----------
@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():
    db = get_db()
    total_doctors = db.execute("SELECT COUNT(*) c FROM doctors").fetchone()["c"]
    total_patients = db.execute("SELECT COUNT(*) c FROM patients").fetchone()["c"]
    
    # Total Upcoming
    total_upcoming = db.execute("""
        SELECT COUNT(*) c FROM appointments 
        WHERE datetime(date||' '||time) >= datetime('now') AND status='Booked'
    """).fetchone()["c"]
    
    # Upcoming appointments
    upcoming = db.execute("""
      SELECT a.id, u.full_name patient_name, u2.full_name doctor_name, a.date, a.time, a.status
      FROM appointments a
      JOIN patients p ON a.patient_id=p.id
      JOIN users u ON p.user_id = u.id
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users u2 ON d.user_id = u2.id
      WHERE datetime(a.date||' '||a.time) >= datetime('now') AND a.status='Booked'
      ORDER BY a.date, a.time LIMIT 10
    """).fetchall()

    # Past activity
    past = db.execute("""
      SELECT a.id, u.full_name patient_name, u2.full_name doctor_name, a.date, a.time, a.status
      FROM appointments a
      JOIN patients p ON a.patient_id=p.id
      JOIN users u ON p.user_id = u.id
      JOIN doctors d ON a.doctor_id = d.id
      JOIN users u2 ON d.user_id = u2.id
      WHERE datetime(a.date||' '||a.time) < datetime('now') OR a.status != 'Booked'
      ORDER BY a.date DESC, a.time DESC LIMIT 10
    """).fetchall()

    return render_template("admin_dashboard.html", 
                           total_doctors=total_doctors,
                           total_patients=total_patients, 
                           total_upcoming=total_upcoming,
                           upcoming=upcoming, past=past)

@app.route("/admin/doctors", methods=["GET","POST"])
@login_required(role="admin")
def manage_doctors():
    db = get_db()
    q = request.args.get("q", "").strip()
    
    if request.method=="POST":
        username = request.form["username"].strip()
        full_name = request.form["full_name"].strip()
        email = request.form["email"].strip()
        phone = request.form["phone"].strip()
        password = request.form["password"]
        dept = request.form["department"].strip()
        experience = request.form.get("experience","" ).strip()
        cur = db.execute("SELECT id FROM departments WHERE name=?", (dept,))
        row = cur.fetchone()
        if not row:
            db.execute("INSERT INTO departments (name,description) VALUES (?,?)", (dept, dept+" department"))
            dept_id = db.execute("SELECT id FROM departments WHERE name=?", (dept,)).fetchone()["id"]
        else:
            dept_id = row["id"]
        try:
            ph = generate_password_hash(password)
            cur = db.execute("INSERT INTO users (username,password_hash,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
                             (username, ph, "doctor", full_name, email, phone))
            user_id = cur.lastrowid
            db.execute("INSERT INTO doctors (user_id,department_id,experience) VALUES (?,?,?)",
                       (user_id, dept_id, experience or None))
            db.commit()
            flash("Doctor added.", "success")
        except sqlite3.IntegrityError:
            flash("Username exists.", "danger")
    
    # Fetch doctors with search filter
    query = """
      SELECT d.id, u.full_name, u.username, u.email, u.phone, dep.name department, d.experience
      FROM doctors d JOIN users u ON d.user_id = u.id LEFT JOIN departments dep ON d.department_id=dep.id
    """
    params = []
    if q:
        query += " WHERE u.full_name LIKE ? OR u.username LIKE ? OR u.email LIKE ?"
        like = f"%{q}%"
        params = [like, like, like]
    
    query += " ORDER BY u.full_name"
    
    doctors = db.execute(query, params).fetchall()
    return render_template("admin_doctors.html", doctors=doctors, q=q)

@app.route("/admin/doctors/<int:doctor_id>/edit", methods=["GET","POST"])
@login_required(role="admin")
def admin_edit_doctor(doctor_id):
    db = get_db()
    doctor = db.execute("""
      SELECT d.id,d.user_id, u.username, u.full_name, u.email, u.phone, d.experience, d.department_id
      FROM doctors d JOIN users u ON d.user_id = u.id WHERE d.id = ?
    """, (doctor_id,)).fetchone()
    if not doctor:
        flash("Doctor not found.", "danger"); return redirect(url_for("manage_doctors"))
    departments = db.execute("SELECT id,name FROM departments ORDER BY name").fetchall()
    if request.method=="POST":
        full_name = request.form.get("full_name"," ").strip()
        email = request.form.get("email"," ").strip()
        phone = request.form.get("phone"," ").strip()
        dept_id = request.form.get("department") or None
        experience = request.form.get("experience", "").strip()
        if not full_name: flash("Name required.", "warning"); return redirect(url_for("admin_edit_doctor", doctor_id=doctor_id))
        db.execute("UPDATE users SET full_name=?, email=?, phone=? WHERE id=?", (full_name, email, phone, doctor["user_id"]))
        db.execute("UPDATE doctors SET department_id=?, experience=? WHERE id=?", (dept_id, experience or None, doctor_id))
        db.commit()
        flash("Doctor updated.", "success")
        return redirect(url_for("admin_view_doctor", doctor_id=doctor_id))
    return render_template("admin_edit_doctor.html", doctor=doctor, departments=departments)

@app.route("/admin/doctors/<int:doctor_id>")
@login_required(role="admin")
def admin_view_doctor(doctor_id):
    db = get_db()
    doctor = db.execute("""
            SELECT d.id,d.user_id,u.username,u.full_name,u.email,u.phone,d.experience, dep.name AS department, u.is_active
            FROM doctors d JOIN users u ON d.user_id = u.id LEFT JOIN departments dep ON d.department_id=dep.id WHERE d.id=?
        """, (doctor_id,)).fetchone()
    if not doctor:
        flash("Doctor not found.", "danger")
        return redirect(url_for("manage_doctors"))
    appts = db.execute("""
      SELECT a.id,a.date,a.time,a.status, u_p.full_name patient_name
      FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users u_p ON p.user_id=u_p.id
      WHERE a.doctor_id=? ORDER BY datetime(a.date||' '||a.time) DESC LIMIT 50
    """, (doctor_id,)).fetchall()
    return render_template("admin_view_doctor.html", doctor=doctor, appts=appts)

@app.route("/admin/doctors/<int:doctor_id>/delete", methods=["POST"])
@login_required(role="admin")
def admin_delete_doctor(doctor_id):
    db = get_db()
    d = db.execute("SELECT * FROM doctors WHERE id=?", (doctor_id,)).fetchone()
    if not d: flash("Doctor not found.", "danger")
    else:
        db.execute("UPDATE users SET is_active=0 WHERE id=?", (d["user_id"],))
        db.execute("DELETE FROM doctors WHERE id=?", (doctor_id,))
        db.commit()
        flash("Doctor removed.", "success")
    return redirect(url_for("manage_doctors"))

@app.route("/admin/patients")
@login_required(role="admin")
def admin_list_patients():
    q = request.args.get("q","").strip()
    db=get_db()
    if q:
        like=f"%{q}%"
        patients=db.execute("""
          SELECT p.id,u.id as user_id,u.username,u.full_name,u.email,u.phone,u.is_active
          FROM patients p JOIN users u ON p.user_id=u.id
          WHERE u.full_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR u.phone LIKE ?
          ORDER BY u.full_name
        """,(like,like,like,like)).fetchall()
    else:
        patients=db.execute("SELECT p.id,u.id as user_id,u.username,u.full_name,u.email,u.phone,u.is_active FROM patients p JOIN users u ON p.user_id=u.id ORDER BY u.full_name").fetchall()
    return render_template("admin_patients.html", patients=patients, q=q)

@app.route("/admin/patients/<int:patient_id>")
@login_required(role="admin")
def admin_view_patient(patient_id):
    db=get_db()
    patient=db.execute("""
      SELECT p.id AS patient_id, u.id AS user_id, u.username, u.full_name, u.email, u.phone, p.address, p.blood_group, p.emergency_contact, p.age
      FROM patients p JOIN users u ON p.user_id=u.id WHERE p.id=?
    """,(patient_id,)).fetchone()
    
    if not patient: 
        flash("Patient not found.", "danger")
        return redirect(url_for("admin_list_patients"))
    
    # MERGED QUERY: Gets Appointments + Treatment details in one go
    appointments=db.execute("""
      SELECT a.id, a.date, a.time, a.end_time, a.status,
             d.id as doctor_id, u_d.full_name doctor_name,
             t.diagnosis, t.prescription
      FROM appointments a 
      JOIN doctors d ON a.doctor_id=d.id 
      JOIN users u_d ON d.user_id=u_d.id
      LEFT JOIN treatments t ON t.appointment_id = a.id
      WHERE a.patient_id=? 
      ORDER BY datetime(a.date||' '||a.time) DESC
    """,(patient_id,)).fetchall()
    
    return render_template("admin_view_patient.html", patient=patient, appointments=appointments)

@app.route("/admin/users/<int:user_id>/deactivate", methods=["POST"])
@login_required(role="admin")
def admin_deactivate_user(user_id):
    db = get_db()
    user = db.execute("SELECT is_active FROM users WHERE id=?", (user_id,)).fetchone()
    if user:
        new_status = 0 if user["is_active"] else 1
        db.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, user_id))
        db.commit()
        status_text = "activated" if new_status else "deactivated"
        flash(f"User {status_text}.", "success")
    else:
        flash("User not found.", "danger")
    return redirect(request.referrer or url_for("admin_dashboard"))

@app.route("/admin/appointments/<int:appointment_id>/cancel", methods=["POST"])
@login_required(role="admin")
def admin_cancel_appointment(appointment_id):
    db = get_db()
    appt = db.execute("SELECT id, doctor_id, date, time, status, patient_id FROM appointments WHERE id=?", (appointment_id,)).fetchone()
    if not appt:
        flash("Appointment not found.", "danger")
    elif appt["status"] != "Booked":
        flash("Only booked appointments can be cancelled.", "warning")
    else:
        # Update status
        db.execute("UPDATE appointments SET status = 'Cancelled' WHERE id = ?", (appointment_id,))
        # Release slot
        db.execute("""
            UPDATE doctor_availability
            SET is_booked = 0, booked_by = NULL, booked_at = NULL
            WHERE doctor_id = ? AND date = ? AND start_time = ?
        """, (appt["doctor_id"], appt["date"], appt["time"]))
        db.commit()
        flash("Appointment cancelled successfully.", "success")
        
    return redirect(request.referrer or url_for('admin_appointments'))

@app.route("/admin/departments", methods=["GET","POST"])
@login_required(role="admin")
def admin_departments():
    db=get_db()
    if request.method=="POST":
        name=request.form.get("name","" ).strip()
        desc = request.form.get("description","" ).strip()
        if not name: flash("Name required.", "warning"); return redirect(url_for("admin_departments"))
        try:
            db.execute("INSERT INTO departments (name,description) VALUES (?,?)",(name,desc or None))
            db.commit()
            flash("Department added.", "success")
        except sqlite3.IntegrityError:
            flash("Already exists.", "danger")
        return redirect(url_for("admin_departments"))
    depts=db.execute("""
        SELECT dep.id, dep.name, dep.description, COUNT(d.id) as doctor_count
        FROM departments dep
        LEFT JOIN doctors d ON dep.id = d.department_id
        GROUP BY dep.id
        ORDER BY dep.name
    """).fetchall()
    return render_template("admin_departments.html", depts=depts)

@app.route("/admin/departments/<int:dept_id>/edit", methods=["GET", "POST"])
@login_required(role="admin")
def admin_edit_department(dept_id):
    db = get_db()
    dept = db.execute("SELECT * FROM departments WHERE id=?", (dept_id,)).fetchone()
    if not dept:
        flash("Department not found.", "danger")
        return redirect(url_for("admin_departments"))
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name:
            flash("Name required.", "warning")
        else:
            try:
                db.execute("UPDATE departments SET name=?, description=? WHERE id=?", (name, description, dept_id))
                db.commit()
                flash("Department updated.", "success")
                return redirect(url_for("admin_departments"))
            except sqlite3.IntegrityError:
                flash("Department name already exists.", "danger")
                
    return render_template("admin_edit_department.html", dept=dept)

@app.route("/admin/appointments")
@login_required(role="admin")
def admin_appointments():
    db = get_db()
    filter_type = request.args.get("filter", "all")
    
    query = """
      SELECT a.id, a.date, a.time, a.end_time, a.status,
             u_p.full_name patient_name, u_p.phone patient_phone,
             u_d.full_name doctor_name, dep.name department
      FROM appointments a
      JOIN patients p ON a.patient_id=p.id
      JOIN users u_p ON p.user_id=u_p.id
      JOIN doctors d ON a.doctor_id=d.id
      JOIN users u_d ON d.user_id=u_d.id
      LEFT JOIN departments dep ON d.department_id=dep.id
    """
    
    params = []
    if filter_type == 'upcoming':
        query += " WHERE datetime(a.date||' '||a.time) >= datetime('now') AND a.status='Booked'"
        query += " ORDER BY a.date ASC, a.time ASC"
    elif filter_type == 'past':
        query += " WHERE datetime(a.date||' '||a.time) < datetime('now') OR a.status != 'Booked'"
        query += " ORDER BY a.date DESC, a.time DESC"
    else:
        query += " ORDER BY a.date DESC, a.time DESC"
        
    query += " LIMIT 1000"
    
    rows = db.execute(query, params).fetchall()
    return render_template("admin_appointments.html", rows=rows, filter_type=filter_type)

# -------- Doctor routes ----------

@app.route("/doctor/patient/<int:patient_id>/history")
@login_required(role="doctor")
def doctor_view_patient_history(patient_id):
    """
    Show the full treatment history for a patient (for the doctor).
    """
    db = get_db()
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for("logout"))

    # ensure doctor has at least one appointment with this patient (security)
    rel = db.execute("""
        SELECT 1 FROM appointments WHERE doctor_id = ? AND patient_id = ? LIMIT 1
    """, (doctor["id"], patient_id)).fetchone()
    if not rel:
        flash("You have not been assigned this patient.", "danger")
        return redirect(url_for("doctor_dashboard"))

    # fetch patient info
    patient = db.execute("""
        SELECT p.id AS patient_id, u.full_name, u.email, u.phone, p.address, p.blood_group
        FROM patients p JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (patient_id,)).fetchone()

    # fetch appointments and treatments
    records = db.execute("""
        SELECT a.id AS appt_id, a.date, a.time, a.end_time, a.status,
             a.doctor_id as doctor_id, t.diagnosis, t.prescription, t.notes,
               u.full_name AS doctor_name
        FROM appointments a
        LEFT JOIN treatments t ON t.appointment_id = a.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        LEFT JOIN users u ON d.user_id = u.id
        WHERE a.patient_id = ? AND a.status = 'Completed'
        ORDER BY a.date DESC, a.time DESC
    """, (patient_id,)).fetchall()

    return render_template("doctor_view_patient_history.html", patient=patient, records=records, current_doctor_id=doctor['id'])

# ---------- Doctor routes ----------

# ------------------ Replace doctor_dashboard ------------------
@app.route("/doctor/dashboard")
@login_required(role="doctor")
def doctor_dashboard():
    db = get_db()
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for("logout"))

    # Stats Calculations
    total_patients = db.execute("""
        SELECT COUNT(DISTINCT patient_id) c FROM appointments WHERE doctor_id = ?
    """, (doctor["id"],)).fetchone()["c"]

    active_count = db.execute("""
        SELECT COUNT(*) c FROM appointments 
        WHERE doctor_id = ? AND datetime(date||' '||time) >= datetime('now') AND status='Booked'
    """, (doctor["id"],)).fetchone()["c"]

    today_count = db.execute("""
        SELECT COUNT(*) c FROM appointments 
        WHERE doctor_id = ? AND date = ? AND status='Booked'
    """, (doctor["id"], date.today().isoformat())).fetchone()["c"]


    # Active (Actionable: Booked)
    active_appts = db.execute("""
        SELECT a.id, a.date, a.time, a.end_time, a.status,
               p.id AS patient_id, u.full_name AS patient_name, u.phone AS patient_phone
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE a.doctor_id = ? AND a.status = 'Booked'
        ORDER BY a.date ASC, a.time ASC
    """, (doctor["id"],)).fetchall()

    # Patients (for the "My Patients" section)
    patients = db.execute("""
        SELECT DISTINCT p.id AS patient_id, u.full_name, u.phone, u.email
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE a.doctor_id = ?
        ORDER BY u.full_name
    """, (doctor["id"],)).fetchall()

    return render_template("doctor_dashboard.html", 
                           active_appts=active_appts, 
                           patients=patients,
                           total_patients=total_patients,
                           active_count=active_count,
                           today_count=today_count,
                           doctor=doctor) # Pass doctor object for ID display

@app.route("/doctor/appointments/<int:appointment_id>/complete", methods=["GET", "POST"])
@login_required(role="doctor")
def doctor_complete_appointment(appointment_id):
    db = get_db()
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for("logout"))

    appt = db.execute("""
        SELECT a.id, a.date, a.time, a.end_time, a.status, a.patient_id,
               u.full_name AS patient_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE a.id = ? AND a.doctor_id = ?
    """, (appointment_id, doctor["id"])).fetchone()

    if not appt:
        flash("Appointment not found.", "danger")
        return redirect(url_for("doctor_dashboard"))

    # Prevent completing if already completed or cancelled
    if request.method == "GET":
        # If already completed, show the treatment (if any) but do not allow editing
        treatment = db.execute("""
            SELECT diagnosis, prescription, notes FROM treatments WHERE appointment_id = ?
        """, (appointment_id,)).fetchone()
        # also get prior treatments for this patient (excluding current appointment)
        past_treatments = db.execute("""
            SELECT t.diagnosis, t.prescription, t.notes, a.date AS appt_date, a.time AS appt_time
            FROM treatments t
            JOIN appointments a ON t.appointment_id = a.id
            WHERE a.patient_id = ? AND a.id != ?
            ORDER BY a.date DESC, a.time DESC
            LIMIT 20
        """, (appt["patient_id"], appointment_id)).fetchall()
        return render_template("doctor_complete.html", appt=appt, treatment=treatment, past_treatments=past_treatments)

    # POST: doctor is submitting diagnosis/prescription/notes to mark completed OR update existing treatment
    if appt["status"] == "Cancelled":
        flash("Cannot add or edit treatment for a cancelled appointment.", "warning")
        return redirect(url_for("doctor_dashboard"))

    diagnosis = request.form.get("diagnosis", "").strip()
    prescription = request.form.get("prescription", "").strip()
    notes = request.form.get("notes", "").strip()

    try:
        if appt["status"] == "Booked":
            db.execute("UPDATE appointments SET status = 'Completed' WHERE id = ?", (appointment_id,))
        db.execute("""
            INSERT OR REPLACE INTO treatments (appointment_id, diagnosis, prescription, notes)
            VALUES (?, ?, ?, ?)
        """, (appointment_id, diagnosis, prescription, notes))
        db.commit()
        if appt["status"] == "Booked":
            flash("Appointment marked as completed and treatment saved.", "success")
        else:
            flash("Treatment updated.", "success")
    except Exception as e:
        db.rollback()
        flash("Failed to complete appointment: " + str(e), "danger")

    # After saving, redirect to the patient history view for this appointment
    return redirect(url_for("doctor_view_patient_history", patient_id=appt["patient_id"]))

# ------------------ Add doctor_cancel_appointment ------------------
@app.route("/doctor/appointments/<int:appointment_id>/cancel", methods=["POST"])
@login_required(role="doctor")
def doctor_cancel_appointment(appointment_id):
    db = get_db()
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for("logout"))

    appt = db.execute("SELECT * FROM appointments WHERE id = ? AND doctor_id = ?", (appointment_id, doctor["id"])).fetchone()
    if not appt:
        flash("Appointment not found.", "danger")
        return redirect(url_for("doctor_dashboard"))

    # If already cancelled or completed, don't re-cancel
    if appt["status"] == "Cancelled":
        flash("Appointment already cancelled.", "info")
        return redirect(url_for("doctor_dashboard"))
    if appt["status"] == "Completed":
        flash("Cannot cancel a completed appointment.", "warning")
        return redirect(url_for("doctor_dashboard"))

    try:
        # Update appointment status
        db.execute("UPDATE appointments SET status = 'Cancelled' WHERE id = ?", (appointment_id,))

        # Release any corresponding availability slot booked by this patient at same doctor/date/time
        db.execute("""
            UPDATE doctor_availability
            SET is_booked = 0, booked_by = NULL, booked_at = NULL
            WHERE doctor_id = ? AND date = ? AND start_time = ? AND booked_by = ?
        """, (doctor["id"], appt["date"], appt["time"], appt["patient_id"]))

        db.commit()
        flash("Appointment cancelled and slot released.", "info")
    except Exception as e:
        db.rollback()
        flash("Failed to cancel appointment: " + str(e), "danger")

    return redirect(url_for("doctor_dashboard"))

# ------------------ Add doctor_patient_history ------------------
@app.route("/doctor/patients/<int:patient_id>/history")
@login_required(role="doctor")
def doctor_patient_history(patient_id):
    db = get_db()
    # doctor must exist (ensure logged-in is doctor)
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for("logout"))

    # load patient and history
    patient = db.execute("""
        SELECT p.id AS patient_id, u.full_name, u.email, u.phone, p.address, p.blood_group
        FROM patients p JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (patient_id,)).fetchone()

    if not patient:
        flash("Patient not found.", "danger")
        return redirect(url_for("doctor_dashboard"))

    appointments = db.execute("""
        SELECT a.id, a.date, a.time, a.end_time, a.status,
               d.id AS doctor_id, u2.full_name AS doctor_name
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        JOIN users u2 ON d.user_id = u2.id
        WHERE a.patient_id = ?
        ORDER BY datetime(a.date || ' ' || a.time) DESC
        LIMIT 500
    """, (patient_id,)).fetchall()

    treatments = db.execute("""
        SELECT t.id, t.appointment_id, t.diagnosis, t.prescription, t.notes,
               a.date AS appt_date, a.time AS appt_time,
               u2.full_name AS doctor_name
        FROM treatments t
        JOIN appointments a ON t.appointment_id = a.id
        JOIN doctors d2 ON a.doctor_id = d2.id
        JOIN users u2 ON d2.user_id = u2.id
        WHERE a.patient_id = ?
        ORDER BY a.date DESC, a.time DESC
    """, (patient_id,)).fetchall()

    return render_template("doctor_patient_history.html", patient=patient, appointments=appointments, treatments=treatments)


@app.route("/doctor/patient/<int:patient_id>")
@login_required(role="doctor")
def doctor_view_patient(patient_id):
    db = get_db()
    user_id = session["user_id"]
    doc = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doc:
        flash("Doctor not found.", "danger")
        return redirect(url_for("logout"))

    # get patient details (user row)
    patient = db.execute("""
        SELECT p.id AS patient_internal_id, u.id AS user_id, u.username, u.full_name, u.email, u.phone,
               p.address, p.blood_group, p.emergency_contact
        FROM patients p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (patient_id,)).fetchone()

    if not patient:
        flash("Patient not found.", "danger")
        return redirect(url_for("doctor_dashboard"))

    # get appointments and any treatments for this patient (doctor can view all)
    appointments = db.execute("""
        SELECT t.id AS treatment_id, t.diagnosis, t.prescription, t.notes,
               a.date AS appt_date, a.time AS appt_time, a.status,
               u2.full_name AS doctor_name
        FROM appointments a
        LEFT JOIN treatments t ON t.appointment_id = a.id
        LEFT JOIN doctors d2 ON a.doctor_id = d2.id
        LEFT JOIN users u2 ON d2.user_id = u2.id
        WHERE a.patient_id = ?
        ORDER BY a.date DESC, a.time DESC
    """, (patient_id,)).fetchall()

    return render_template("doctor_view_patient.html", patient=patient, appointments=appointments)



@app.route("/doctor/availability", methods=["GET", "POST"])
@login_required(role="doctor")
def doctor_availability():
    """
    Doctor sets availability for the next 7 days in bulk.
    This view:
      - accepts a slot_length and per-day enabled/start/end values
      - deletes only unbooked availability rows for affected dates
      - generates discrete slots of slot_length minutes for enabled days
      - on GET: returns next-7-day items and a small summary (total slots / booked slots)
    """
    db = get_db()
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for("logout"))

    # Prepare next 7 days
    today = date.today()
    days = []
    for i in range(7):
        dd = today + timedelta(days=i)
        days.append({
            "iso": dd.isoformat(),
            "label": dd.strftime("%A"),  # weekday name
        })

    time_slots = generate_time_slots()

    if request.method == "POST":
        # slot length in minutes
        try:
            slot_length = int(request.form.get("slot_length", "15"))
        except ValueError:
            flash("Invalid slot length.", "warning")
            return redirect(url_for("doctor_availability"))

        if slot_length <= 0 or slot_length % 5 != 0:
            flash("Slot length must be a positive multiple of 5 minutes.", "warning")
            return redirect(url_for("doctor_availability"))

        # Collect changes for each day
        to_process = []  # list of (date_iso, start_time, end_time)
        for d in days:
            iso = d["iso"]
            enabled = request.form.get(f"enable_{iso}")  # exists if checked
            if not enabled:
                # If unchecked, we will remove unbooked availability for this date (doctor may choose to disable)
                to_process.append((iso, None, None))
                continue

            start_time = request.form.get(f"start_{iso}", "").strip()
            end_time = request.form.get(f"end_{iso}", "").strip()

            # validate times
            try:
                datetime.strptime(start_time, "%H:%M")
                datetime.strptime(end_time, "%H:%M")
            except Exception:
                flash(f"Invalid time format for {iso}.", "warning")
                return redirect(url_for("doctor_availability"))

            if not (is_5min_multiple(start_time) and is_5min_multiple(end_time)):
                flash(f"Times for {iso} must be multiples of 5 minutes.", "warning")
                return redirect(url_for("doctor_availability"))

            if not (is_within_bounds(start_time) and is_within_bounds(end_time)):
                flash(f"Times on {iso} must be between 09:00 and 21:00.", "warning")
                return redirect(url_for("doctor_availability"))

            if time_to_minutes(start_time) >= time_to_minutes(end_time):
                flash(f"End time must be after start time for {iso}.", "warning")
                return redirect(url_for("doctor_availability"))

            to_process.append((iso, start_time, end_time))

        try:
            # perform updates per day
            for iso, start_time, end_time in to_process:
                # Remove only unbooked availability rows for this doctor/date (preserve booked ones)
                db.execute("""
                    DELETE FROM doctor_availability
                    WHERE doctor_id = ? AND date = ? AND is_booked = 0
                """, (doctor["id"], iso))

                # If day was disabled (start_time is None), continue to next
                if start_time is None:
                    continue

                # Generate discrete slots of slot_length minutes between start_time (inclusive) and end_time (exclusive)
                cursor = time_to_minutes(start_time)
                end_min = time_to_minutes(end_time)

                # create slots until (cursor + slot_length) <= end_min
                while cursor + slot_length <= end_min:
                    s_h = cursor // 60
                    s_m = cursor % 60
                    slot_s = f"{s_h:02d}:{s_m:02d}"

                    e_min = cursor + slot_length
                    e_h = e_min // 60
                    e_m = e_min % 60
                    slot_e = f"{e_h:02d}:{e_m:02d}"

                    try:
                        db.execute("""
                            INSERT INTO doctor_availability (doctor_id, date, start_time, end_time)
                            VALUES (?, ?, ?, ?)
                        """, (doctor["id"], iso, slot_s, slot_e))
                    except sqlite3.IntegrityError:
                        # unique index could prevent duplicates; safe to ignore
                        pass

                    cursor += slot_length

            db.commit()
            flash("Availability updated for next 7 days.", "success")
            return redirect(url_for("doctor_availability"))
        except Exception as e:
            db.rollback()
            flash("Failed to update availability: " + str(e), "danger")
            return redirect(url_for("doctor_availability"))

    # GET: show current availability summary for the next 7 days
    placeholders = ",".join("?" for _ in days)
    params = [doctor["id"]] + [d["iso"] for d in days]
    rows = db.execute(f"""
        SELECT id, date, start_time, end_time, is_booked
        FROM doctor_availability
        WHERE doctor_id = ? AND date IN ({placeholders})
        ORDER BY date, start_time
    """, params).fetchall()

    # group rows by date
    avail_by_date = {d["iso"]: [] for d in days}
    for r in rows:
        avail_by_date[r["date"]].append(r)

    # For GET, build items (earliest start, latest end) and compute summary counts
    items = []
    slots_summary = {}  # date_iso -> {"total": int, "booked": int}
    for d in days:
        iso = d["iso"]
        day_rows = avail_by_date.get(iso, [])
        if day_rows:
            # compute earliest start and latest end
            starts = [time_to_minutes(r["start_time"]) for r in day_rows]
            ends = [time_to_minutes(r["end_time"]) for r in day_rows]
            s_min = min(starts)
            e_max = max(ends)
            s_str = f"{s_min//60:02d}:{s_min%60:02d}"
            e_str = f"{e_max//60:02d}:{e_max%60:02d}"
            enabled = True
        else:
            # default
            s_str = "09:00"
            e_str = "17:00"
            enabled = False

        # compute summary counts
        total = len(day_rows)
        booked = sum(1 for r in day_rows if r["is_booked"])
        slots_summary[iso] = {"total": total, "booked": booked}

        items.append({
            "iso": iso,
            "label": d["label"],
            "enabled": enabled,
            "start_time": s_str,
            "end_time": e_str,
        })

    return render_template(
        "doctor_availability.html",
        days=items,
        time_slots=time_slots,
        slots_summary=slots_summary
    )




@app.route("/doctor/patients")
@login_required(role="doctor")
def doctor_assigned_patients():
    db = get_db()
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id = ?", (user_id,)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for("logout"))

    patients = db.execute("""
        SELECT DISTINCT p.id AS patient_id, u.full_name, u.phone, u.email
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE a.doctor_id = ?
        ORDER BY u.full_name
    """, (doctor["id"],)).fetchall()

    return render_template("doctor_patients.html", patients=patients, hide_nav=True)


# -------- Patient routes ----------
@app.route("/patient/dashboard")
@login_required(role="patient")
def patient_dashboard():
    db=get_db()
    user_id=session["user_id"]
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (user_id,)).fetchone()
    if not patient: flash("Profile missing.", "danger"); return redirect(url_for("logout"))
    
    # Upcoming
    upcoming = db.execute("""
      SELECT a.id,a.date,a.time,a.end_time,a.status,u.full_name AS doctor_name, d.id AS doctor_id
      FROM appointments a JOIN doctors d ON a.doctor_id=d.id JOIN users u ON d.user_id=u.id
      WHERE a.patient_id=? AND datetime(a.date||' '||a.time) >= datetime('now') AND a.status='Booked'
      ORDER BY a.date,a.time
    """,(patient["id"],)).fetchall()
    
    # Past
    past = db.execute("""
            SELECT a.id,a.date,a.time,a.end_time,a.status,u.full_name AS doctor_name,t.diagnosis,t.prescription,t.notes
            FROM appointments a JOIN doctors d ON a.doctor_id=d.id JOIN users u ON d.user_id=u.id LEFT JOIN treatments t ON t.appointment_id=a.id
            WHERE a.patient_id=? AND (datetime(a.date||' '||a.time) < datetime('now') OR a.status = 'Completed')
            ORDER BY a.date DESC, a.time DESC
    """,(patient["id"],)).fetchall()
    
    # Departments (for "Browse by Specialization")
    departments = db.execute("SELECT name FROM departments ORDER BY name").fetchall()

    # Available Doctors (Top 4 for Preview)
    doctors = db.execute("""
      SELECT d.id,u.full_name, dep.name AS department
      FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id 
      ORDER BY dep.name, u.full_name LIMIT 4
    """).fetchall()

    # --- Search Logic ---
    q = request.args.get("q", "").strip()
    search_results = []
    if q:
        like = f"%{q}%"
        search_results = db.execute("""
          SELECT d.id, u.full_name, dep.name AS department, u.username
          FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id
          WHERE u.full_name LIKE ? OR dep.name LIKE ? OR u.username LIKE ?
          ORDER BY u.full_name
        """, (like, like, like)).fetchall()
    
    return render_template("patient_dashboard.html", 
                           patient=patient, # Added patient object to template context
                           upcoming=upcoming, 
                           past=past, 
                           departments=departments, 
                           doctors=doctors, 
                           search_results=search_results, 
                           q=q)

@app.route("/patient/doctor/<int:doctor_id>/availability")
@login_required(role="patient")
def patient_view_doctor_availability(doctor_id):
    db=get_db()
    doctor=db.execute("SELECT d.id,u.full_name, dep.name AS department FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id WHERE d.id=?", (doctor_id,)).fetchone()
    if not doctor: flash("Doctor not found.", "danger"); return redirect(url_for("patient_dashboard"))
    
    # Fetch slots - broadly filtering by date first to reduce load
    # We use 'localtime' modifier for sqlite if possible, but python filtering is safer
    db_slots = db.execute("SELECT id,date,start_time,end_time,is_booked FROM doctor_availability WHERE doctor_id=? AND is_booked=0 ORDER BY date,start_time", (doctor_id,)).fetchall()
    
    # Filter in Python
    now = datetime.now()
    valid_slots = []
    for s in db_slots:
        # Construct slot datetime
        # s['date'] is 'YYYY-MM-DD', s['start_time'] is 'HH:MM'
        try:
            slot_dt = datetime.strptime(f"{s['date']} {s['start_time']}", "%Y-%m-%d %H:%M")
            if slot_dt > now:
                valid_slots.append(s)
        except ValueError:
            continue # Skip invalid formats

    return render_template("patient_doctor_slots.html", doctor=doctor, slots=valid_slots)



@app.route("/patient/appointments/book/<int:slot_id>", methods=["GET","POST"])
@login_required(role="patient")
def patient_book_slot(slot_id):
    db=get_db()
    user_id=session["user_id"]
    patient=db.execute("SELECT * FROM patients WHERE user_id=?", (user_id,)).fetchone()
    if not patient: flash("Profile missing.", "danger"); return redirect(url_for("logout"))
    slot = db.execute("""SELECT da.id, da.doctor_id, da.date, da.start_time, da.end_time, d.id as doc_id, u.full_name as doctor_name, da.is_booked
                        FROM doctor_availability da JOIN doctors d ON da.doctor_id=d.id JOIN users u ON d.user_id=u.id WHERE da.id=?""",(slot_id,)).fetchone()
    if not slot: flash("Slot not found.", "danger"); return redirect(url_for("patient_dashboard"))
    if request.method=="GET":
        return render_template("patient_confirm_book.html", slot=slot)
    try:
        db.execute("BEGIN IMMEDIATE")
        fresh=db.execute("SELECT id,is_booked,doctor_id,date,start_time,end_time FROM doctor_availability WHERE id=?", (slot_id,)).fetchone()
        if not fresh or fresh["is_booked"]==1:
            db.execute("ROLLBACK"); flash("Slot already booked.", "danger"); return redirect(url_for("patient_dashboard"))
        doc_id=fresh["doctor_id"]
        conflict = db.execute("SELECT 1 FROM appointments WHERE patient_id=? AND doctor_id=? AND date=? AND time=? AND status='Booked'", (patient["id"], doc_id, fresh["date"], fresh["start_time"])).fetchone()
        if conflict:
            db.execute("ROLLBACK"); flash("You already have booking at this time.", "warning"); return redirect(url_for("patient_dashboard"))
        
        # Insert booking
        cur = db.execute("INSERT INTO appointments (patient_id,doctor_id,date,time,end_time,status,created_at) VALUES (?,?,?,?,?,'Booked',?)", (patient["id"], doc_id, fresh["date"], fresh["start_time"], fresh["end_time"], datetime.utcnow().isoformat()))
        appt_id = cur.lastrowid # Capture new appt ID
        
        db.execute("UPDATE doctor_availability SET is_booked=1, booked_by=?, booked_at=datetime('now','localtime') WHERE id=?", (patient["id"], slot_id))
        db.commit()
        
        # Redirect to new Success Page with ID
        return render_template("patient_booking_success.html", appt_id=appt_id)
        
    except Exception as e:
        try: db.execute("ROLLBACK")
        except: pass
        flash("Booking failed: "+str(e), "danger"); return redirect(url_for("patient_dashboard"))

@app.route("/patient/appointments/<int:appointment_id>/cancel", methods=["POST"])
@login_required(role="patient")
def patient_cancel_appointment(appointment_id):
    db = get_db()
    appt = db.execute(
        "SELECT id, doctor_id, date, time, status FROM appointments WHERE id = ?",
        (appointment_id,)
    ).fetchone()

    if not appt:
        flash("Appointment not found.", "danger")
        return redirect(url_for("patient_dashboard"))

    # Only allow cancelling if currently Booked
    if appt["status"] != "Booked":
        flash(f"Cannot cancel an appointment with status '{appt['status']}'.", "warning")
        return redirect(url_for("patient_dashboard"))

    db.execute("UPDATE appointments SET status = 'Cancelled' WHERE id = ?", (appointment_id,))
    db.execute("""
        UPDATE doctor_availability
        SET is_booked = 0, booked_by = NULL, booked_at = NULL
        WHERE doctor_id = ? AND date = ? AND start_time = ?
    """, (appt["doctor_id"], appt["date"], appt["time"]))
    db.commit()
    flash("Appointment cancelled and slot released.", "info")
    return redirect(url_for("patient_dashboard"))


@app.route("/patient/appointments/<int:appointment_id>/request_reschedule", methods=["GET", "POST"])
@login_required(role="patient")
def patient_request_reschedule(appointment_id):
    """
    GET: show available unbooked slots for the appointment's doctor (same as before).
    POST: if selected slot is available, perform an immediate reschedule without requiring doctor approval.
    """
    db = get_db()
    user_id = session["user_id"]
    patient = db.execute("SELECT * FROM patients WHERE user_id = ?", (user_id,)).fetchone()
    if not patient:
        flash("Patient not found.", "danger")
        return redirect(url_for("patient_dashboard"))

    appt = db.execute("SELECT * FROM appointments WHERE id = ?", (appointment_id,)).fetchone()
    if not appt or appt["patient_id"] != patient["id"]:
        flash("Appointment not found.", "danger")
        return redirect(url_for("patient_dashboard"))

    # list available slots for this doctor (unbooked and >= today)
    db_slots = db.execute("""
        SELECT id, date, start_time, end_time
        FROM doctor_availability
        WHERE doctor_id = ? AND is_booked = 0
        ORDER BY date, start_time
    """, (appt["doctor_id"],)).fetchall()

    # Filter in Python
    now = datetime.now()
    valid_slots = []
    for s in db_slots:
        try:
            slot_dt = datetime.strptime(f"{s['date']} {s['start_time']}", "%Y-%m-%d %H:%M")
            if slot_dt > now:
                valid_slots.append(s)
        except ValueError:
            continue 
            
    if request.method == "POST":
        # patient selected a slot to move to
        try:
            requested_slot_id = int(request.form.get("requested_slot_id"))
        except (TypeError, ValueError):
            flash("Please select a valid slot.", "warning")
            return redirect(url_for("patient_request_reschedule", appointment_id=appointment_id))

        # fetch the slot with a row lock pattern (we will use a BEGIN IMMEDIATE)
        try:
            db.execute("BEGIN IMMEDIATE")
        except Exception:
            # fallback: if cannot get immediate lock, continue - sqlite should still work
            pass

        fresh = db.execute("""
            SELECT * FROM doctor_availability WHERE id = ?
        """, (requested_slot_id,)).fetchone()

        if not fresh:
            try:
                db.execute("ROLLBACK")
            except:
                pass
            flash("Selected slot no longer exists.", "danger")
            return redirect(url_for("patient_request_reschedule", appointment_id=appointment_id))

        if fresh["is_booked"]:
            try:
                db.execute("ROLLBACK")
            except:
                pass
            flash("Selected slot was just booked by someone else. Please choose another slot.", "danger")
            return redirect(url_for("patient_request_reschedule", appointment_id=appointment_id))

        # ensure slot belongs to the same doctor
        if fresh["doctor_id"] != appt["doctor_id"]:
            try:
                db.execute("ROLLBACK")
            except:
                pass
            flash("Selected slot belongs to a different doctor.", "danger")
            return redirect(url_for("patient_request_reschedule", appointment_id=appointment_id))

        try:
            # Free the old booked availability row for this appointment (if any).
            # There might not be a matching availability row (if the appointment was created externally),
            # so don't assume — just try to free any row matching doctor/date/time and booked_by = patient_id.
            db.execute("""
                UPDATE doctor_availability
                SET is_booked = 0, booked_by = NULL, booked_at = NULL
                WHERE doctor_id = ? AND date = ? AND start_time = ? AND booked_by = ?
            """, (appt["doctor_id"], appt["date"], appt["time"], patient["id"]))

            # Update the appointment to the new time
            db.execute("""
                UPDATE appointments
                SET date = ?, time = ?, end_time = ?, status = 'Booked'
                WHERE id = ?
            """, (fresh["date"], fresh["start_time"], fresh["end_time"], appointment_id))

            # Book the new slot
            db.execute("""
                UPDATE doctor_availability
                SET is_booked = 1, booked_by = ?, booked_at = datetime('now', 'localtime')
                WHERE id = ?
            """, (patient["id"], requested_slot_id))

            db.commit()
            flash("Appointment rescheduled successfully.", "success")
            return redirect(url_for("patient_dashboard"))

        except Exception as e:
            try:
                db.execute("ROLLBACK")
            except:
                pass
            flash("Failed to reschedule appointment: " + str(e), "danger")
            return redirect(url_for("patient_request_reschedule", appointment_id=appointment_id))

    # GET - render the selection page
    return render_template("patient_request_reschedule.html", appt=appt, slots=valid_slots)


@app.route("/patient/profile", methods=["GET","POST"])
@login_required(role="patient")
def patient_profile():
    db=get_db()
    user_id=session["user_id"]
    user=db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    patient=db.execute("SELECT * FROM patients WHERE user_id=?", (user_id,)).fetchone()
    if request.method=="POST":
        full_name=request.form.get("full_name","").strip()
        email=request.form.get("email","").strip()
        phone=request.form.get("phone","").strip()
        address=request.form.get("address","").strip()
        blood_group=request.form.get("blood_group","").strip()
        emergency_contact=request.form.get("emergency_contact","").strip()
        if not full_name: flash("Full name required.", "warning"); return redirect(url_for("patient_profile"))
        db.execute("UPDATE users SET full_name=?, email=?, phone=? WHERE id=?", (full_name, email, phone, user_id))
        db.execute("UPDATE patients SET address=?, blood_group=?, emergency_contact=? WHERE user_id=?", (address or None, blood_group or None, emergency_contact or None, user_id))
        db.commit(); session["full_name"]=full_name; flash("Profile updated.", "success"); return redirect(url_for("patient_profile"))
    return render_template("patient_profile.html", user=user, patient=patient)

@app.route("/patient/doctors/all")
@login_required(role="patient")
def patient_all_doctors():
    db = get_db()
    doctors = db.execute("""
      SELECT d.id,u.full_name, dep.name AS department
      FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id ORDER BY dep.name,u.full_name
    """).fetchall()
    return render_template("patient_all_doctors.html", doctors=doctors)

# --- RE-ADDED THIS ROUTE TO FIX CRASHES ---
@app.route("/search/doctors")
@login_required()
def search_doctors():
    # Redirects old search requests to the main dashboard
    return redirect(url_for('patient_dashboard'))

@app.route("/doctor/<int:doctor_id>/profile")
@login_required(role="patient")
def patient_view_doctor_profile(doctor_id):
    db=get_db()
    doctor=db.execute("SELECT d.id,u.full_name,u.email,u.phone,d.experience,dep.name AS department FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id WHERE d.id=?", (doctor_id,)).fetchone()
    if not doctor: flash("Doctor not found.", "danger"); return redirect(url_for("patient_dashboard"))
    return render_template("patient_view_doctor.html", doctor=doctor)

# -------- Run ----------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    # default run
    app.run(debug=True)
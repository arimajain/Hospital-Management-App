from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g
)
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date

# Project Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hospital.db")

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_key" 

# --- Database Connection ---
def get_db():
    """Connects to the database."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    """Closes the connection when the request ends."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

# --- Initialization ---
def init_db():
    """Creates tables if they don't exist."""
    db = get_db()
    
    # Create Tables
    db.execute("""CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','doctor','patient')),
      full_name TEXT, email TEXT, phone TEXT, is_active INTEGER DEFAULT 1
    );""")
    
    db.execute("""CREATE TABLE IF NOT EXISTS departments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT
    );""")
    
    db.execute("""CREATE TABLE IF NOT EXISTS doctors (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE NOT NULL,
        department_id INTEGER, experience TEXT, bio TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(department_id) REFERENCES departments(id)
    );""")
    
    db.execute("""CREATE TABLE IF NOT EXISTS patients (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE NOT NULL,
      address TEXT, blood_group TEXT, emergency_contact TEXT, age INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );""")
    
    db.execute("""CREATE TABLE IF NOT EXISTS appointments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL,
      date TEXT NOT NULL, time TEXT NOT NULL, end_time TEXT,
      status TEXT NOT NULL DEFAULT 'Booked', created_at TEXT NOT NULL,
      FOREIGN KEY(patient_id) REFERENCES patients(id), FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    );""")
    
    db.execute("""CREATE TABLE IF NOT EXISTS treatments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, appointment_id INTEGER UNIQUE NOT NULL,
      diagnosis TEXT, prescription TEXT, notes TEXT,
      FOREIGN KEY(appointment_id) REFERENCES appointments(id)
    );""")
    
    db.execute("""CREATE TABLE IF NOT EXISTS doctor_availability (
      id INTEGER PRIMARY KEY AUTOINCREMENT, doctor_id INTEGER NOT NULL,
      date TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL,
      is_booked INTEGER DEFAULT 0, booked_by INTEGER, booked_at TEXT,
      FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    );""")
    
    # Migration: Ensure age column exists
    try:
        db.execute("ALTER TABLE patients ADD COLUMN age INTEGER")
    except sqlite3.OperationalError:
        pass

    # Default Admin
    if not db.execute("SELECT id FROM users WHERE role='admin'").fetchone():
        pw = generate_password_hash("admin123")
        db.execute("INSERT INTO users (username,password_hash,role,full_name,email) VALUES (?,?,?,?,?)",
                   ("admin", pw, "admin", "Default Admin", "admin@example.com"))
        db.commit()
        print("Created default admin.")

# --- Utils ---
def generate_time_slots():
    """Generates time options from 09:00 to 21:00."""
    slots = []
    for h in range(9, 21):
        for m in range(0, 60, 5):
            slots.append(f"{h:02d}:{m:02d}")
    slots.append("21:00")
    return slots

def time_to_minutes(t):
    h, m = map(int, t.split(":"))
    return h * 60 + m

def login_required(role=None):
    """Protects routes to ensure user is logged in and has correct role."""
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session: return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Access denied.", "danger")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# --- Routes ---
@app.route("/")
def index():
    if "user_id" in session:
        r = session.get("role")
        if r == "admin": return redirect(url_for("admin_dashboard"))
        if r == "doctor": return redirect(url_for("doctor_dashboard"))
        return redirect(url_for("patient_dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE username=? AND is_active=1", (u,)).fetchone()
        if user and check_password_hash(user["password_hash"], p):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            return redirect(url_for("index"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register_patient():
    if request.method == "POST":
        if request.form["password"] != request.form["confirm"]:
            flash("Passwords do not match.", "danger")
            return render_template("register_patient.html")
        
        db = get_db()
        try:
            pw = generate_password_hash(request.form["password"])
            cur = db.execute("INSERT INTO users (username,password_hash,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
                             (request.form["username"], pw, "patient", request.form["full_name"], request.form["email"], request.form["phone"]))
            db.execute("INSERT INTO patients (user_id) VALUES (?)", (cur.lastrowid,))
            db.commit()
            flash("Registered successfully.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username exists.", "danger")
    return render_template("register_patient.html")

# --- Admin ---
@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():
    db = get_db()
    doc_c = db.execute("SELECT COUNT(*) c FROM doctors").fetchone()["c"]
    pat_c = db.execute("SELECT COUNT(*) c FROM patients").fetchone()["c"]
    up_c = db.execute("SELECT COUNT(*) c FROM appointments WHERE datetime(date||' '||time) >= datetime('now') AND status='Booked'").fetchone()["c"]
    
    upcoming = db.execute("""
      SELECT a.id, u.full_name patient_name, u2.full_name doctor_name, a.date, a.time, a.status
      FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users u ON p.user_id=u.id JOIN doctors d ON a.doctor_id=d.id JOIN users u2 ON d.user_id=u2.id
      WHERE datetime(a.date||' '||a.time) >= datetime('now') AND a.status='Booked' ORDER BY a.date, a.time LIMIT 10
    """).fetchall()
    
    past = db.execute("""
      SELECT a.id, u.full_name patient_name, u2.full_name doctor_name, a.date, a.time, a.status
      FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users u ON p.user_id=u.id JOIN doctors d ON a.doctor_id=d.id JOIN users u2 ON d.user_id=u2.id
      WHERE datetime(a.date||' '||a.time) < datetime('now') OR a.status != 'Booked' ORDER BY a.date DESC, a.time DESC LIMIT 10
    """).fetchall()

    return render_template("admin_dashboard.html", total_doctors=doc_c, total_patients=pat_c, total_upcoming=up_c, upcoming=upcoming, past=past)

@app.route("/admin/doctors", methods=["GET", "POST"])
@login_required(role="admin")
def manage_doctors():
    db = get_db()
    q = request.args.get("q", "").strip()
    if request.method == "POST":
        try:
            pw = generate_password_hash(request.form["password"])
            dept_row = db.execute("SELECT id FROM departments WHERE name=?", (request.form["department"],)).fetchone()
            if not dept_row:
                db.execute("INSERT INTO departments (name) VALUES (?)", (request.form["department"],))
                dept_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            else:
                dept_id = dept_row["id"]
                
            cur = db.execute("INSERT INTO users (username,password_hash,role,full_name,email,phone) VALUES (?,?,?,?,?,?)",
                       (request.form["username"], pw, "doctor", request.form["full_name"], request.form["email"], request.form["phone"]))
            db.execute("INSERT INTO doctors (user_id, department_id, experience) VALUES (?,?,?)",
                       (cur.lastrowid, dept_id, request.form.get("experience")))
            db.commit()
            flash("Doctor added.", "success")
        except sqlite3.IntegrityError:
            flash("Error adding doctor.", "danger")

    # SEARCH FIX: Added "OR dep.name LIKE ?" to allow searching by specialization
    query = """
        SELECT d.id, u.full_name, u.username, u.email, u.phone, dep.name department, d.experience 
        FROM doctors d 
        JOIN users u ON d.user_id=u.id 
        LEFT JOIN departments dep ON d.department_id=dep.id
    """
    params = []
    if q:
        query += " WHERE u.full_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR dep.name LIKE ?"
        like = f"%{q}%"
        params = [like, like, like, like]
        
    query += " ORDER BY u.full_name"
    
    doctors = db.execute(query, params).fetchall()
    return render_template("admin_doctors.html", doctors=doctors, q=q)

@app.route("/admin/doctors/<int:doctor_id>")
@login_required(role="admin")
def admin_view_doctor(doctor_id):
    db = get_db()
    doctor = db.execute("SELECT d.id, u.username, u.full_name, u.email, u.phone, u.is_active, d.experience, dep.name as department FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id WHERE d.id=?", (doctor_id,)).fetchone()
    appts = db.execute("SELECT a.id, a.date, a.time, a.status, u.full_name as patient_name FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users u ON p.user_id=u.id WHERE a.doctor_id=? ORDER BY a.date DESC LIMIT 20", (doctor_id,)).fetchall()
    return render_template("admin_view_doctor.html", doctor=doctor, appts=appts)

@app.route("/admin/doctors/<int:doctor_id>/edit", methods=["GET","POST"])
@login_required(role="admin")
def admin_edit_doctor(doctor_id):
    db = get_db()
    doctor = db.execute("SELECT d.*, u.full_name, u.email, u.phone FROM doctors d JOIN users u ON d.user_id=u.id WHERE d.id=?", (doctor_id,)).fetchone()
    if request.method == "POST":
        db.execute("UPDATE users SET full_name=?, email=?, phone=? WHERE id=?", (request.form["full_name"], request.form["email"], request.form["phone"], doctor["user_id"]))
        db.execute("UPDATE doctors SET experience=? WHERE id=?", (request.form["experience"], doctor_id))
        db.commit()
        return redirect(url_for("admin_view_doctor", doctor_id=doctor_id))
    depts = db.execute("SELECT * FROM departments").fetchall()
    return render_template("admin_edit_doctor.html", doctor=doctor, departments=depts)

@app.route("/admin/doctors/<int:doctor_id>/delete", methods=["POST"])
@login_required(role="admin")
def admin_delete_doctor(doctor_id):
    db = get_db()
    uid = db.execute("SELECT user_id FROM doctors WHERE id=?", (doctor_id,)).fetchone()["user_id"]
    db.execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    flash("Doctor deactivated.", "success")
    return redirect(url_for("manage_doctors"))

@app.route("/admin/patients")
@login_required(role="admin")
def admin_list_patients():
    db = get_db()
    q = request.args.get("q", "").strip()
    sql = "SELECT p.id, u.id as user_id, u.full_name, u.username, u.email, u.phone, u.is_active FROM patients p JOIN users u ON p.user_id=u.id"
    if q: sql += f" WHERE u.full_name LIKE '%{q}%' OR u.username LIKE '%{q}%'"
    return render_template("admin_patients.html", patients=db.execute(sql).fetchall(), q=q)

@app.route("/admin/patients/<int:patient_id>")
@login_required(role="admin")
def admin_view_patient(patient_id):
    db = get_db()
    patient = db.execute("SELECT p.id, u.full_name, u.username, u.email, u.phone, p.address, p.blood_group, p.emergency_contact, p.age FROM patients p JOIN users u ON p.user_id=u.id WHERE p.id=?", (patient_id,)).fetchone()
    appointments = db.execute("SELECT a.id, a.date, a.time, a.status, d.id as doctor_id, u.full_name as doctor_name, t.diagnosis, t.prescription FROM appointments a JOIN doctors d ON a.doctor_id=d.id JOIN users u ON d.user_id=u.id LEFT JOIN treatments t ON t.appointment_id=a.id WHERE a.patient_id=? ORDER BY a.date DESC", (patient_id,)).fetchall()
    return render_template("admin_view_patient.html", patient=patient, appointments=appointments)

@app.route("/admin/users/<int:user_id>/deactivate", methods=["POST"])
@login_required(role="admin")
def admin_deactivate_user(user_id):
    db = get_db()
    curr = db.execute("SELECT is_active FROM users WHERE id=?", (user_id,)).fetchone()["is_active"]
    db.execute("UPDATE users SET is_active=? WHERE id=?", (0 if curr else 1, user_id))
    db.commit()
    return redirect(request.referrer)

@app.route("/admin/departments", methods=["GET", "POST"])
@login_required(role="admin")
def admin_departments():
    db = get_db()
    if request.method == "POST":
        try:
            db.execute("INSERT INTO departments (name, description) VALUES (?, ?)", (request.form["name"], request.form.get("description")))
            db.commit()
        except: pass
    depts = db.execute("SELECT dep.id, dep.name, dep.description, COUNT(d.id) as doctor_count FROM departments dep LEFT JOIN doctors d ON dep.id=d.department_id GROUP BY dep.id ORDER BY dep.name").fetchall()
    return render_template("admin_departments.html", depts=depts)

@app.route("/admin/departments/<int:dept_id>/edit", methods=["GET", "POST"])
@login_required(role="admin")
def admin_edit_department(dept_id):
    db = get_db()
    if request.method=="POST":
        db.execute("UPDATE departments SET name=?, description=? WHERE id=?", (request.form["name"], request.form["description"], dept_id))
        db.commit()
        return redirect(url_for("admin_departments"))
    dept = db.execute("SELECT * FROM departments WHERE id=?", (dept_id,)).fetchone()
    return render_template("admin_edit_department.html", dept=dept)

@app.route("/admin/appointments")
@login_required(role="admin")
def admin_appointments():
    db = get_db()
    ft = request.args.get("filter", "all")
    sql = """SELECT a.id, a.date, a.time, a.status, up.full_name as patient_name, up.phone as patient_phone, ud.full_name as doctor_name, dep.name as department 
             FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users up ON p.user_id=up.id 
             JOIN doctors d ON a.doctor_id=d.id JOIN users ud ON d.user_id=ud.id LEFT JOIN departments dep ON d.department_id=dep.id"""
    if ft == 'upcoming': sql += " WHERE datetime(a.date||' '||a.time) >= datetime('now') AND a.status='Booked' ORDER BY a.date, a.time"
    elif ft == 'past': sql += " WHERE datetime(a.date||' '||a.time) < datetime('now') OR a.status != 'Booked' ORDER BY a.date DESC"
    else: sql += " ORDER BY a.date DESC"
    rows = db.execute(sql + " LIMIT 1000").fetchall()
    return render_template("admin_appointments.html", rows=rows, filter_type=ft)

# --- Doctor ---
@app.route("/doctor/dashboard")
@login_required(role="doctor")
def doctor_dashboard():
    db = get_db()
    user_id = session["user_id"]
    doctor = db.execute("SELECT * FROM doctors WHERE user_id=?", (user_id,)).fetchone()
    
    pat_count = db.execute("SELECT COUNT(DISTINCT patient_id) c FROM appointments WHERE doctor_id=?", (doctor["id"],)).fetchone()["c"]
    today_count = db.execute("SELECT COUNT(*) c FROM appointments WHERE doctor_id=? AND date=? AND status='Booked'", (doctor["id"], date.today().isoformat())).fetchone()["c"]
    active_count = db.execute("SELECT COUNT(*) c FROM appointments WHERE doctor_id=? AND datetime(date||' '||time) >= datetime('now') AND status='Booked'", (doctor["id"],)).fetchone()["c"]
    
    active_appts = db.execute("""
        SELECT a.id, a.date, a.time, u.full_name as patient_name, p.id as patient_id 
        FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users u ON p.user_id=u.id
        WHERE a.doctor_id=? AND a.status='Booked' ORDER BY a.date, a.time
    """, (doctor["id"],)).fetchall()
    
    patients = db.execute("SELECT DISTINCT p.id as patient_id, u.full_name, u.phone FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users u ON p.user_id=u.id WHERE a.doctor_id=?", (doctor["id"],)).fetchall()
    
    return render_template("doctor_dashboard.html", doctor=doctor, total_patients=pat_count, today_count=today_count, active_count=active_count, active_appts=active_appts, patients=patients)

@app.route("/doctor/availability", methods=["GET", "POST"])
@login_required(role="doctor")
def doctor_availability():
    db = get_db()
    doc_id = db.execute("SELECT id FROM doctors WHERE user_id=?", (session["user_id"],)).fetchone()["id"]
    
    days = []
    for i in range(7):
        d = date.today() + timedelta(days=i)
        days.append({"iso": d.isoformat(), "label": d.strftime("%A")})
        
    if request.method == "POST":
        slot = int(request.form.get("slot_length", "15"))
        for d in days:
            iso = d["iso"]
            if request.form.get(f"enable_{iso}"):
                # 1. Clear unbooked slots for this day to avoid duplicates
                db.execute("DELETE FROM doctor_availability WHERE doctor_id=? AND date=? AND is_booked=0", (doc_id, iso))
                
                # 2. Generate new slots
                start, end = request.form.get(f"start_{iso}"), request.form.get(f"end_{iso}")
                curr, limit = time_to_minutes(start), time_to_minutes(end)
                
                while curr + slot <= limit:
                    s_str = f"{curr//60:02d}:{curr%60:02d}"
                    e_str = f"{(curr+slot)//60:02d}:{(curr+slot)%60:02d}"
                    
                    # FIX: Use INSERT OR IGNORE to prevent crashes if a booked slot already exists at this time
                    db.execute("""
                        INSERT OR IGNORE INTO doctor_availability 
                        (doctor_id, date, start_time, end_time, is_booked) 
                        VALUES (?, ?, ?, ?, 0)
                    """, (doc_id, iso, s_str, e_str))
                    
                    curr += slot
        db.commit()
        flash("Availability updated successfully.", "success")
        return redirect(url_for('doctor_availability')) 

    # Load saved state
    slots_summary = {}
    for d in days:
        existing = db.execute("SELECT start_time, end_time, is_booked FROM doctor_availability WHERE doctor_id=? AND date=? ORDER BY start_time", (doc_id, d["iso"])).fetchall()
        count = len(existing)
        slots_summary[d["iso"]] = {"total": count, "booked": sum(1 for s in existing if s["is_booked"])}
        
        if count > 0:
            d["enabled"] = True
            d["start_time"] = existing[0]["start_time"]
            d["end_time"] = existing[-1]["end_time"]
        else:
            d["enabled"] = False
            d["start_time"] = "09:00"
            d["end_time"] = "17:00"

    return render_template("doctor_availability.html", days=days, time_slots=generate_time_slots(), slots_summary=slots_summary)
@app.route("/doctor/complete/<int:appointment_id>", methods=["GET", "POST"])
@login_required(role="doctor")
def doctor_complete_appointment(appointment_id):
    db = get_db()
    if request.method=="POST":
        db.execute("UPDATE appointments SET status='Completed' WHERE id=?", (appointment_id,))
        db.execute("INSERT OR REPLACE INTO treatments (appointment_id, diagnosis, prescription, notes) VALUES (?,?,?,?)",
                   (appointment_id, request.form["diagnosis"], request.form["prescription"], request.form["notes"]))
        db.commit()
        return redirect(url_for("doctor_dashboard"))
        
    appt = db.execute("SELECT a.*, u.full_name as patient_name FROM appointments a JOIN patients p ON a.patient_id=p.id JOIN users u ON p.user_id=u.id WHERE a.id=?", (appointment_id,)).fetchone()
    treatment = db.execute("SELECT * FROM treatments WHERE appointment_id=?", (appointment_id,)).fetchone()
    past = db.execute("SELECT a.date as appt_date, a.time as appt_time, t.* FROM treatments t JOIN appointments a ON t.appointment_id=a.id WHERE a.patient_id=? AND a.id!=? ORDER BY a.date DESC", (appt["patient_id"], appointment_id)).fetchall()
    return render_template("doctor_complete.html", appt=appt, treatment=treatment, past_treatments=past)

@app.route("/doctor/patient/<int:patient_id>/history")
@login_required(role="doctor")
def doctor_view_patient_history(patient_id):
    db = get_db()
    doc = db.execute("SELECT id FROM doctors WHERE user_id=?", (session["user_id"],)).fetchone()
    patient = db.execute("SELECT p.id as patient_id, u.full_name, u.email, u.phone, p.address, p.blood_group, p.age FROM patients p JOIN users u ON p.user_id=u.id WHERE p.id=?", (patient_id,)).fetchone()
    records = db.execute("SELECT a.id as appt_id, a.date, a.time, a.status, a.doctor_id, t.diagnosis, t.prescription, t.notes FROM appointments a LEFT JOIN treatments t ON t.appointment_id=a.id WHERE a.patient_id=? AND a.status='Completed' ORDER BY a.date DESC", (patient_id,)).fetchall()
    return render_template("doctor_view_patient_history.html", patient=patient, records=records, current_doctor_id=doc["id"])

@app.route("/doctor/patients")
def doctor_assigned_patients(): return redirect(url_for("doctor_dashboard"))

# --- Patient ---
@app.route("/patient/dashboard")
@login_required(role="patient")
def patient_dashboard():
    db = get_db()
    user_id = session["user_id"]
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (user_id,)).fetchone()
    
    q = request.args.get("q", "").strip()
    search_results = []
    if q:
        search_results = db.execute("""
          SELECT d.id, u.full_name, dep.name as department 
          FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id 
          WHERE u.full_name LIKE ? OR dep.name LIKE ? OR u.username LIKE ?
        """, (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
        
    upcoming = db.execute("SELECT a.id, a.date, a.time, a.status, u.full_name as doctor_name, d.id as doctor_id FROM appointments a JOIN doctors d ON a.doctor_id=d.id JOIN users u ON d.user_id=u.id WHERE a.patient_id=? AND datetime(a.date||' '||a.time) >= datetime('now') AND a.status='Booked' ORDER BY a.date, a.time", (patient["id"],)).fetchall()
    past = db.execute("SELECT a.id, a.date, a.time, a.status, u.full_name as doctor_name, t.diagnosis, t.prescription, t.notes FROM appointments a JOIN doctors d ON a.doctor_id=d.id JOIN users u ON d.user_id=u.id LEFT JOIN treatments t ON t.appointment_id=a.id WHERE a.patient_id=? AND (datetime(a.date||' '||a.time) < datetime('now') OR a.status!='Booked') ORDER BY a.date DESC", (patient["id"],)).fetchall()
    
    depts = db.execute("SELECT name FROM departments ORDER BY name").fetchall()
    docs = db.execute("SELECT d.id, u.full_name, dep.name as department FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id LIMIT 4").fetchall()
    
    return render_template("patient_dashboard.html", patient=patient, upcoming=upcoming, past=past, departments=depts, doctors=docs, search_results=search_results, q=q)

@app.route("/patient/doctor/<int:doctor_id>/availability")
@login_required(role="patient")
def patient_view_doctor_availability(doctor_id):
    db = get_db()
    doctor = db.execute("SELECT d.id, u.full_name, dep.name as department FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id WHERE d.id=?", (doctor_id,)).fetchone()
    slots = db.execute("SELECT * FROM doctor_availability WHERE doctor_id=? AND is_booked=0 ORDER BY date, start_time", (doctor_id,)).fetchall()
    valid = [s for s in slots if datetime.strptime(f"{s['date']} {s['start_time']}", "%Y-%m-%d %H:%M") > datetime.now()]
    return render_template("patient_doctor_slots.html", doctor=doctor, slots=valid)

@app.route("/patient/book/<int:slot_id>", methods=["GET", "POST"])
@login_required(role="patient")
def patient_book_slot(slot_id):
    db = get_db()
    slot = db.execute("SELECT da.*, u.full_name as doctor_name FROM doctor_availability da JOIN doctors d ON da.doctor_id=d.id JOIN users u ON d.user_id=u.id WHERE da.id=?", (slot_id,)).fetchone()
    
    if request.method == "POST":
        pat = db.execute("SELECT id FROM patients WHERE user_id=?", (session["user_id"],)).fetchone()
        try:
            cur = db.execute("INSERT INTO appointments (patient_id, doctor_id, date, time, end_time, status, created_at) VALUES (?,?,?,?,?,?,?)",
                       (pat["id"], slot["doctor_id"], slot["date"], slot["start_time"], slot["end_time"], 'Booked', datetime.now().isoformat()))
            db.execute("UPDATE doctor_availability SET is_booked=1 WHERE id=?", (slot_id,))
            db.commit()
            return render_template("patient_booking_success.html", appt_id=cur.lastrowid)
        except:
            db.rollback()
            flash("Booking failed.", "danger")
    return render_template("patient_confirm_book.html", slot=slot)

@app.route("/patient/profile", methods=["GET", "POST"])
@login_required(role="patient")
def patient_profile():
    db = get_db()
    uid = session["user_id"]
    if request.method == "POST":
        db.execute("UPDATE users SET full_name=?, email=?, phone=? WHERE id=?", (request.form["full_name"], request.form["email"], request.form["phone"], uid))
        db.execute("UPDATE patients SET address=?, blood_group=?, emergency_contact=?, age=? WHERE user_id=?",
                   (request.form["address"], request.form["blood_group"], request.form["emergency_contact"], request.form["age"], uid))
        db.commit()
        session["full_name"] = request.form["full_name"]
        flash("Profile updated.", "success")
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (uid,)).fetchone()
    return render_template("patient_profile.html", user=user, patient=patient)

@app.route("/patient/doctors/all")
def patient_all_doctors():
    db = get_db()
    docs = db.execute("SELECT d.id, u.full_name, dep.name as department FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id ORDER BY u.full_name").fetchall()
    return render_template("patient_all_doctors.html", doctors=docs)

@app.route("/search/doctors")
def search_doctors(): return redirect(url_for("patient_dashboard"))

@app.route("/doctor/<int:doctor_id>/profile")
@login_required(role="patient")
def patient_view_doctor_profile(doctor_id):
    db = get_db()
    # FIX: Removed 'd.bio' to prevent crash
    doctor = db.execute("SELECT d.id, u.full_name, u.email, u.phone, d.experience, dep.name as department FROM doctors d JOIN users u ON d.user_id=u.id LEFT JOIN departments dep ON d.department_id=dep.id WHERE d.id=?", (doctor_id,)).fetchone()
    return render_template("patient_view_doctor.html", doctor=doctor)

# --- Shared Cancel ---
@app.route("/appointment/<int:appointment_id>/cancel", methods=["POST"])
@login_required()
def shared_cancel_appointment(appointment_id):
    db = get_db()
    appt = db.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchone()
    if appt and appt["status"] == 'Booked':
        db.execute("UPDATE appointments SET status='Cancelled' WHERE id=?", (appointment_id,))
        db.execute("UPDATE doctor_availability SET is_booked=0 WHERE doctor_id=? AND date=? AND start_time=?", 
                   (appt["doctor_id"], appt["date"], appt["time"]))
        db.commit()
        flash("Appointment cancelled.", "info")
    return redirect(request.referrer or url_for('index'))

admin_cancel_appointment = shared_cancel_appointment
doctor_cancel_appointment = shared_cancel_appointment
patient_cancel_appointment = shared_cancel_appointment
app.add_url_rule('/admin/cancel/<int:appointment_id>', 'admin_cancel_appointment', shared_cancel_appointment, methods=['POST'])
app.add_url_rule('/doctor/cancel/<int:appointment_id>', 'doctor_cancel_appointment', shared_cancel_appointment, methods=['POST'])
app.add_url_rule('/patient/cancel/<int:appointment_id>', 'patient_cancel_appointment', shared_cancel_appointment, methods=['POST'])

@app.route("/patient/reschedule/<int:appointment_id>", methods=["GET", "POST"])
@login_required(role="patient")
def patient_request_reschedule(appointment_id):
    db = get_db()
    appt = db.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchone()
    if request.method == "POST":
        new_id = request.form.get("requested_slot_id")
        slot = db.execute("SELECT * FROM doctor_availability WHERE id=?", (new_id,)).fetchone()
        db.execute("UPDATE doctor_availability SET is_booked=0 WHERE doctor_id=? AND date=? AND start_time=?", (appt["doctor_id"], appt["date"], appt["time"]))
        db.execute("UPDATE appointments SET date=?, time=?, end_time=? WHERE id=?", (slot["date"], slot["start_time"], slot["end_time"], appointment_id))
        db.execute("UPDATE doctor_availability SET is_booked=1 WHERE id=?", (new_id,))
        db.commit()
        flash("Rescheduled.", "success")
        return redirect(url_for("patient_dashboard"))
    slots = db.execute("SELECT * FROM doctor_availability WHERE doctor_id=? AND is_booked=0", (appt["doctor_id"],)).fetchall()
    valid = [s for s in slots if datetime.strptime(f"{s['date']} {s['start_time']}", "%Y-%m-%d %H:%M") > datetime.now()]
    return render_template("patient_request_reschedule.html", appt=appt, slots=valid)

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)
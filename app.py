import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, login_user, logout_user, login_required,
                         current_user, UserMixin)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, SubmitField, BooleanField,
                     DateField, TimeField, TextAreaField)
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

def normalize_db_url(url: str) -> str:
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url

app = Flask(__name__)
from werkzeug.security import generate_password_hash

with app.app_context():
    from app import db, User  # eğer User modelin aynı dosyadaysa sadece "from app import db, User" yazmana gerek yok
    user = User.query.filter_by(email="mustafaduman7855@gmail.com").first()
    if user and not user.is_admin:
        user.is_admin = True
        db.session.commit()
        print("✅ Kullanıcı admin yapıldı:", user.email)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
db_url = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = normalize_db_url(db_url)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    facility_name = db.Column(db.String(255))
    phone = db.Column(db.String(50))
    is_admin = db.Column(db.Boolean, default=False)
    submissions = db.relationship("Submission", backref="user", lazy=True)

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    match_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    video_link = db.Column(db.String(512))
    notes = db.Column(db.Text)
    consent_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    status = db.Column(db.String(20), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RegisterForm(FlaskForm):
    name = StringField("Ad Soyad", validators=[DataRequired(), Length(max=120)])
    email = StringField("E-posta", validators=[DataRequired(), Email()])
    facility_name = StringField("Tesis Adı", validators=[Length(max=255)])
    phone = StringField("Telefon", validators=[Length(max=50)])
    password = PasswordField("Şifre", validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField("Şifre (tekrar)", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Kayıt Ol")
    def validate_email(self, f):
        if User.query.filter_by(email=f.data.lower()).first():
            raise ValidationError("Bu e-posta ile bir hesap zaten mevcut.")

class LoginForm(FlaskForm):
    email = StringField("E-posta", validators=[DataRequired(), Email()])
    password = PasswordField("Şifre", validators=[DataRequired()])
    remember = BooleanField("Beni hatırla")
    submit = SubmitField("Giriş Yap")

class SubmissionForm(FlaskForm):
    match_date = DateField("Maç Tarihi", validators=[DataRequired()], format="%Y-%m-%d")
    start_time = TimeField("Yayın Başlangıç Saati", validators=[DataRequired()], format="%H:%M")
    end_time = TimeField("Yayın Bitiş Saati", validators=[DataRequired()], format="%H:%M")
    video_link = StringField("Video Linki (opsiyonel)", validators=[Length(max=512)])
    notes = TextAreaField("Açıklama / Notlar (opsiyonel)")
    consent_confirmed = BooleanField(
        "Maçta yer alan tüm oyunculardan internet sitesinde yayın için onay aldığımı beyan ederim.",
        validators=[DataRequired()])
    submit = SubmitField("Bildir")
    def validate_end_time(self, field):
        if self.start_time.data and field.data and self.start_time.data >= field.data:
            raise ValidationError("Bitiş saati başlangıçtan sonra olmalı.")

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

@app.route("/")
def index(): return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        u = User(name=form.name.data.strip(),
                 email=form.email.data.lower().strip(),
                 facility_name=(form.facility_name.data or "").strip() or None,
                 phone=(form.phone.data or "").strip() or None)
        u.set_password(form.password.data)
        admin_email = os.getenv("ADMIN_EMAIL")
        if (User.query.count() == 0) or (admin_email and u.email == admin_email.lower()):
            u.is_admin = True
        db.session.add(u); db.session.commit()
        login_user(u); flash("Kayıt başarılı, hoş geldiniz!", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if u and u.check_password(form.password.data):
            login_user(u, remember=form.remember.data)
            flash("Tekrar hoş geldiniz!", "success"); return redirect(url_for("dashboard"))
        flash("E-posta veya şifre hatalı.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user(); flash("Çıkış yapıldı.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = SubmissionForm()
    if form.validate_on_submit():
        s = Submission(user_id=current_user.id,
                       match_date=form.match_date.data,
                       start_time=form.start_time.data,
                       end_time=form.end_time.data,
                       video_link=(form.video_link.data or "").strip() or None,
                       notes=(form.notes.data or "").strip() or None,
                       consent_confirmed=form.consent_confirmed.data)
        db.session.add(s); db.session.commit()
        flash("Bildirim alındı. En kısa sürede değerlendirilecektir.", "success")
        return redirect(url_for("dashboard"))
    my = Submission.query.filter_by(user_id=current_user.id).order_by(Submission.created_at.desc()).all()
    return render_template("dashboard.html", form=form, my_submissions=my)

def admin_required():
    if not current_user.is_authenticated or not current_user.is_admin: abort(403)

@app.route("/admin")
@login_required
def admin():
    admin_required()
    q = (request.args.get("q","").strip().lower())
    submissions = Submission.query.order_by(Submission.created_at.desc())
    if q:
        submissions = [s for s in submissions
                       if q in (s.user.facility_name or "").lower()
                       or q in (s.user.name or "").lower()
                       or q in (s.user.email or "").lower()]
    else:
        submissions = submissions.all()
    return render_template("admin.html", submissions=submissions)

@app.route("/admin/submission/<int:id>/set_status", methods=["POST"])
@login_required
def set_status(id):
    admin_required()
    status = request.form.get("status", "pending")
    if status not in ["pending","approved","rejected"]:
        flash("Geçersiz durum.", "danger"); return redirect(url_for("admin"))
    s = Submission.query.get_or_404(id); s.status = status; db.session.commit()
    flash("Durum güncellendi.", "success"); return redirect(url_for("admin"))

@app.cli.command("init-db")
def init_db(): db.create_all(); print("Database initialized.")
# Initialize DB tables on startup
with app.app_context():
    db.create_all()

    # --- Force ADMIN_EMAIL as admin every deploy ---
    try:
        admin_email = os.getenv("ADMIN_EMAIL")
        if admin_email:
            u = User.query.filter_by(email=admin_email.lower().strip()).first()
            if u:
                if not u.is_admin:
                    u.is_admin = True
                    db.session.commit()
                    print(f"✅ Admin olarak yükseltildi: {u.email}")
                else:
                    print(f"ℹ️ Zaten admin: {u.email}")
            else:
                print(f"⚠️ ADMIN_EMAIL için kullanıcı yok: {admin_email}")
        else:
            print("⚠️ ADMIN_EMAIL env tanımlı değil.")
    except Exception as e:
        print("⚠️ Admin bootstrap hatası:", e)

import datetime
import secrets

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError

import const
import cloudflare
import mail
from helpers import validate_turnstile, get_subname, generate_key, get_full_domain, generate_subname, format_ns

app = Flask(__name__, template_folder="pages")
app.config["SECRET_KEY"] = const.FLASK_SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{const.DB_USER}:{const.DB_PASSWORD}"
    f"@{const.DB_HOST}/{const.DB_NAME}?charset=utf8mb4"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 3600,
    "pool_pre_ping": True
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120))
    password_hash = db.Column(db.String(256), nullable=False)
    domain_limit = db.Column(db.Integer, default=10)
    domains = db.relationship("Domain", backref="owner", lazy=True)


class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subdomain = db.Column(db.String(255), nullable=False, unique=True)
    ns_records = db.Column(db.JSON, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    user = db.relationship("User", backref="reset_tokens")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory("assets", filename)


@app.route("/")
def index():
    return render_template("index.html", user=current_user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email", "").strip()
        password = request.form["password"]
        captcha = request.form.get("cf-turnstile-response")

        # validate captcha
        if not validate_turnstile(captcha, request.remote_addr):
            flash("CAPTCHA verification failed", "danger")
            return redirect(url_for("register"))

        # input validation
        if len(username) < 3 or len(username) > 50:
            flash("username must be between 3 and 50 characters", "danger")
            return redirect(url_for("register"))

        if not username.isalnum():
            flash("username must be alphanumeric", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("password must be at least 8 characters long", "danger")
            return redirect(url_for("register"))

        # email validation
        try:
            if email:
                mail.send_welcome_email(validate_email(email).normalized, username)
        except EmailNotValidError:
            flash("invalid email address", "danger")
            return redirect(url_for("register"))

        # check if username already exists
        if User.query.filter_by(username=username).first():
            flash("username already exists", "danger")
            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("registration successful!", "success")
        return redirect(url_for("account"))

    return render_template("register.html", turnstile_site_key=const.TURNSTILE_SITE_KEY)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        captcha = request.form.get("cf-turnstile-response")

        if not validate_turnstile(captcha, request.remote_addr):
            flash("CAPTCHA verification failed", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("invalid username or password", "danger")
            return redirect(url_for("login"))

        if not check_password_hash(user.password_hash, password):
            flash("invalid username or password", "danger")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("account"))

    return render_template("login.html", turnstile_site_key=const.TURNSTILE_SITE_KEY)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"].strip()
        username = request.form["username"].strip()
        captcha = request.form.get("cf-turnstile-response")

        # validate captcha
        if not validate_turnstile(captcha, request.remote_addr):
            flash("CAPTCHA verification failed", "danger")
            return redirect(url_for("reset_password"))

        # input validation
        try:
            validate_email(email).normalized  # noqa
        except EmailNotValidError:
            flash("invalid email address", "danger")
            return redirect(url_for("reset_password"))

        user = User.query.filter_by(email=email, username=username).first()
        if not user:
            flash("username or email incorrect", "danger")
            return redirect(url_for("reset_password"))

        # rate limiting
        recent_token = PasswordResetToken.query.filter_by(
            user_id=user.id,
            used=False
        ).order_by(PasswordResetToken.expiry.desc()).first()

        if recent_token and (
                datetime.datetime.now(datetime.timezone.utc) - (recent_token.expiry - datetime.timedelta(hours=1))
        ).total_seconds() < 300:
            # Less than 5 minutes since last request
            flash("a reset email was recently sent. please wait before requesting another.", "warning")
            return redirect(url_for("reset_password"))

        # generate new token
        token = secrets.token_urlsafe(32)
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

        # store in db
        reset_token = PasswordResetToken(
            token=token,
            user_id=user.id,
            expiry=expiry
        )
        db.session.add(reset_token)
        db.session.commit()

        status = mail.send_forgot_password_email(user.email, user.username, token)
        if not status:
            flash("failed to send email! please contact me at freearpa@damcraft.de", "danger")
            return redirect(url_for("reset_password"))

        flash("password reset email sent", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", turnstile_site_key=const.TURNSTILE_SITE_KEY)


# Replace the reset_password_token route in app.py
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_token(token):
    # find and validate token
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()

    if not reset_token or reset_token.expiry < datetime.datetime.now(datetime.timezone.utc):
        flash("invalid or expired token", "danger")
        return redirect(url_for("reset_password"))

    user = User.query.get(reset_token.user_id)
    if not user:
        flash("user not found", "danger")
        return redirect(url_for("reset_password"))

    if request.method == "POST":
        password = request.form["password"]
        if len(password) < 8:
            flash("password must be at least 8 characters long", "danger")
            return redirect(url_for("reset_password_token", token=token))

        user.password_hash = generate_password_hash(password)

        # mark token as used
        reset_token.used = True
        db.session.commit()

        flash("password reset successfully", "success")
        return redirect(url_for("login"))

    return render_template("set_new_password.html", token=token, username=user.username)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("logged out successfully", "success")
    return redirect(url_for("index"))


@app.route("/account")
@login_required
def account():
    return render_template("account.html", user=current_user)


@app.route("/add-domain", methods=["GET", "POST"])
@login_required
def add_domain():
    if current_user.domains and len(current_user.domains) >= current_user.domain_limit:
        flash("domain limit reached", "danger")
        return redirect(url_for("account"))

    if request.method == "POST":
        ns_servers = [format_ns(request.form.getlist(f"ns{i}")[0]) for i in range(1, 6)]
        ns_servers = [ns for ns in ns_servers if ns]  # filter out empty nameservers
        if not ns_servers:
            flash("at least one nameserver required", "danger")
            return redirect(url_for("add_domain"))

        # validate nameserver format
        for ns in ns_servers:
            if not ns or len(ns) > 255 or not all(part.isalnum() or part in "-_." for part in ns):
                flash(f"invalid nameserver format: {ns}", "danger")
                return redirect(url_for("add_domain"))

        # get the subname from the form
        subname = None
        if "domain" in request.form and request.form["domain"].strip():
            full_domain = request.form["domain"].strip()
            subname = get_subname(full_domain)

        if not subname:
            flash("invalid domain name", "danger")
            return redirect(url_for("add_domain"))

        # verify key
        key = request.form.get("key", "").strip()
        if not key or len(key) != 43 or key != generate_key(subname):
            flash("invalid key", "danger")
            return redirect(url_for("add_domain"))

        full_domain = get_full_domain(subname)

        # check if domain already exists
        existing_domain = Domain.query.filter_by(subdomain=full_domain).first()
        if existing_domain:
            flash("this domain is already registered", "danger")
            return redirect(url_for("add_domain"))

        response = cloudflare.create_ns(subname, ns_servers)

        if response.ok:
            domain = Domain(
                subdomain=full_domain,
                ns_records=[ns.strip(".") for ns in ns_servers],
                user_id=current_user.id
            )
            db.session.add(domain)
            db.session.commit()
            flash("domain created successfully", "success")
            return redirect(url_for("account"))
        flash(f"DNS creation failed: {response.text}", "danger")
        return redirect(url_for("add_domain"))

    subname, key = generate_subname()
    return render_template("add_domain.html", domain=get_full_domain(subname), key=key)


@app.route("/edit-domain/<int:domain_id>", methods=["GET", "POST"])
@login_required
def edit_domain(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    if domain.owner != current_user:
        flash("Unauthorized", "danger")
        return redirect(url_for("account"))

    if request.method == "POST":
        new_ns = [format_ns(request.form.getlist(f"ns{i}")[0]) for i in range(1, 6)]
        new_ns = [ns for ns in new_ns if ns]  # filter out empty
        print(new_ns)
        if not new_ns:
            flash("at least one nameserver required", "danger")
            return redirect(url_for("edit_domain", domain_id=domain.id))

        # validate ns format
        for ns in new_ns:
            if not ns or len(ns) > 255 or not all(part.isalnum() or part in "-_." for part in ns):
                flash(f"invalid nameserver format: {ns}", "danger")
                return redirect(url_for("edit_domain", domain_id=domain.id))

        subname = domain.subdomain.removesuffix(f".{const.BASE_DOMAIN}")
        response = cloudflare.update_ns(subname, new_ns)

        if response.ok:
            domain.ns_records = [ns.strip(".") for ns in new_ns]
            db.session.commit()
            flash("records updated successfully", "success")
            return redirect(url_for("account"))
        flash(f"DNS update failed: {response.text}", "danger")

    return render_template("edit_domain.html", domain=domain, nameservers=domain.ns_records)


@app.route("/delete-domain/<int:domain_id>", methods=["POST"])
@login_required
def delete_domain(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    if domain.owner != current_user:
        flash("Unauthorized", "danger")
        return redirect(url_for("account"))

    subname = domain.subdomain.removesuffix(f".{const.BASE_DOMAIN}")
    response = cloudflare.update_ns(subname, [])

    if response.ok:
        db.session.delete(domain)
        db.session.commit()
        flash("domain deleted successfully", "success")
    else:
        flash(f"DNS deletion failed: {response.text}", "danger")

    return redirect(url_for("account"))


@app.route("/cf-ssl")
def cf_ssl():
    return render_template("cf_ssl.html")


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3001, debug=True)

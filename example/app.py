from flask import Flask, render_template_string, request, make_response, redirect

from authlier import AuthlierException, AuthlierManager, authlier_required, current_user, register, login

import os

SESSION_COOKIE_NAME = "sessionid"

user_database = {
    1: {
        "id": 1,
        "username": "beiller",
        "email": "beiller@gmail.com",
        "phone": "12345678901"
    }
}

def create_user(username, email, phone):
    userid = max(user_database.keys()) + 1
    user_data = {
        "id": userid,
        "username": username,
        "email": email,
        "phone": phone
    }
    user_database[userid] = user_data
    return user_data

def make_form(action, method, **kwargs):
    form = f"""<form action="{action}" method="{method}"><ul>"""
    for k, v in kwargs.items():
        form += f"""<li>{k} <input type="text" name="{k}" value="{v}"/></li>"""
    form += """</ul><input type="submit" value="submit" name="submit"/></form>"""
    return form


def create_app():
    app = Flask(__name__)
    
    authlier = AuthlierManager(os.environ["API_KEY"], os.environ["SECRET_KEY"])
    
    @authlier.user_identity_loader
    def user_identity_lookup(user):
        return user["id"]

    # Register a callback function that loads a user from your database whenever
    # a protected route is accessed. This should return any python object on a
    # successful lookup, or None if the lookup failed for any reason (for example
    # if the user has been deleted from the database).
    @authlier.user_lookup_loader
    def user_lookup_callback(metadata: str):
        return user_database[int(metadata)]

    # Tell Authlier how to look up the token (use session cookie)
    @authlier.get_token
    def get_token(context):
        return request.cookies.get(SESSION_COOKIE_NAME, None)


    @app.route('/')
    @authlier_required(optional=True)
    def index():
        if current_user == None:
            return redirect("/login")
        return render_template_string("""Hello, {{ username }}! <a href="/logout">Logout</a>""", username=current_user["username"])

    
    @app.route('/login', methods=['POST', 'GET'])
    def user_login():
        if not request.form:
            return make_form("/login", "post", username="", password="") + """<a href="/register">Register</a>"""

        data = request.form
        try:
            token = login(data['username'], data['password'])
            resp = make_response(redirect("/"))
            resp.set_cookie(SESSION_COOKIE_NAME, token)
            return resp
        except AuthlierException as e:
            return str(e), 400


    @app.route('/register', methods=['GET', 'POST'])
    def user_register():
        if request.form:
            userdata = create_user(request.form.get("username"), request.form.get("email"), request.form.get("phone"))
            token = register(userdata, userdata["username"], request.form.get('password'))
            resp = make_response(redirect("/"))
            resp.set_cookie(SESSION_COOKIE_NAME, token)
            return resp
        return make_form("/register", "post", username="", password="", email="", phone="") + """<a href="/login">Login</a>"""


    @app.route('/logout', methods=['GET'])
    def logout():
        resp = make_response(redirect("/"))
        resp.delete_cookie(SESSION_COOKIE_NAME)
        return resp
    #     try:
    #         jwt.logout(user_lookup_loader(get_token()))
    #         response = {"message": "Logged out successfully."}
    #         return jsonify(response)
    #     except Exception as e:
    #         return f"An error occurred: {str(e)}", 500

    # @app.route('/forgot_password', methods=['POST'])
    # def forgot_password():
    #     data = request.json
    #     try:
    #         jwt.forgot_password(data['email'])
    #         response = {"message": "Password reset email sent successfully."}
    #         return jsonify(response)
    #     except AuthlierException as e:
    #         return str(e), 400

    # @app.route('/profile')
    # def profile():
    #     if current_user is not None and isinstance(current_user, TClass):
    #         user_id = getattr(current_user, "id", None)
    #         username = data['username']
    #         email = data.get('email', "")
    #         return render_template_string(
    #             'Your ID: {{ id }}, Username: {{ username }}, Email: {{ email }}',
    #             id=user_id,
    #             username=username,
    #             email=email
    #         )
    #     else:
    #         return "Please log in."

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)


# Authlier-Flask

## Overview

Authlier-Flask is a lightweight Flask extension that integrates [Authlier](https://authlier.com/) with your application, providing seamless user authentication and session management. This plugin allows you to use Authlier's token-based authentication system within the context of a Flask app.

### Features:
- **User Authentication:** Use Authlier for username/password verification.
- **Session Management:** Maintain user sessions using cookies or tokens.
- **Token-Based Access Control:** Protect routes based on authenticated users.
- **Customizable User Identifiers and Metadata Handling.**

## Installation

To install the `authlier-flask` package, run:

```bash
pip install authlier-flask
```

Alternatively, if you're setting up your project from scratch or using a virtual environment with requirements files, add it to your `requirements.txt`.

### Example `requirements.txt`
```
flask>2.0
authlier-flask
```

## Usage

1. **Initialize Authlier Manager in Your Flask App:**

   Create a new instance of `AuthlierManager` and pass it to each route where you need authentication. Store API_KEY and SECRET_KEY somewhere safe (like environment variables!)

   ```python
   from flask import Flask, redirect, url_for
   from authlier import AuthlierManager, authlier_required

   app = Flask(__name__)

   # Initialize the Authlier Manager with your API key and secret.
   authlier_manager = AuthlierManager(API_KEY, SECRET_KEY)

   @app.route('/')
   def index():
       return 'Welcome to the Home Page!'

   # Protect a route with Authlier
   @authlier_required()
   def protected_route():
       return f'Hello, {current_user.username}! <a href="/logout">Logout</a>'

   if __name__ == '__main__':
       app.run(debug=True)
   ```

2. **Register and Login Users:**

   Use the `register` function to create new users in your system.

   ```python
   from authlier import register

   # Create a user with username, email, phone number.
   def on_new_user():
      return 'beiller', 'beiller@gmail.com', '+1234567890'
   
   registered_user = create_user(*on_new_user())
   print(registered_user)  # Output: {'id': 1, 'username': 'beiller', ...}
   
   # Login a user with username and password.
   def on_login():
      return "user1", "password"
   
   login_response = login(*on_login())  
   ```

3. **Customize User Lookup Loader:**

   Override the default `user_lookup_loader` to customize how users are identified.

   ```python
   @authlier.user_identity_loader
   def user_id(user):
       return str(getattr(user, "id", None))
   
   # Define a custom function for looking up users by metadata.
   @authlier.user_lookup_loader
   def lookup_user(metadata: str):
       return {1: {'id': 1}, 2: {'id': 2}}[int(metadata)]
   ```

4. **Logout Users and Handle Sessions:**

   Use the `logout` function to end a user's session.

   ```python
   from authlier import logout
   
   # Log out the current user.
   def on_logout():
       return "some_token"
   
   success = logout(*on_logout())
   ```

## Contributing

Contributions are welcome! If you find any issues or have suggestions, feel free to open a pull request.

- **GitHub Repository:** [authlier-flask](https://github.com/yourusername/authlier-flask)
  
If you'd like to contribute code, please fork the repository and create new branches for your work. When opening an issue, provide as much detail as possible so that others can help quickly understand and resolve it.

## License

This project is licensed under [MIT](https://choosealicense.com/licenses/mit/).

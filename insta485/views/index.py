"""
Insta485 index (main) view.

URLs include:
/
"""
import os
import hashlib
import uuid
import pathlib
import arrow
import flask
from flask import send_from_directory
import insta485


def logged_in():
    """Check if user is logged in."""
    if 'username' not in flask.session:
        return False
    print(flask.session['username'])
    return True


@insta485.app.route('/')
def show_index():
    """Handle index page."""
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]

    # Query posts from the database
    connection = insta485.model.get_db()

    posts_query = connection.execute(
        """
        SELECT posts.postid, posts.filename, posts.owner, posts.created,
               users.fullname, users.filename AS user_filename,
               COUNT(likes.likeid) AS likes
        FROM posts
        LEFT JOIN likes ON posts.postid = likes.postid
        JOIN users ON posts.owner = users.username
        WHERE posts.owner = ?
           OR posts.owner IN (
               SELECT username2 FROM following WHERE username1 = ?
           )
        GROUP BY posts.postid
        ORDER BY posts.postid DESC
        """,
        (logged_in_user, logged_in_user),
    )
    posts = posts_query.fetchall()

    # Add comments for each post
    for post in posts:
        comments_query = connection.execute(
            """
            SELECT comments.text, comments.owner, users.fullname
            FROM comments
            JOIN users ON comments.owner = users.username
            WHERE comments.postid = ?
            ORDER BY comments.commentid
            """,
            (post["postid"],),
        )
        post["comments"] = comments_query.fetchall()

    # Pass data to the template
    for post in posts:
        # print(post)
        past = post['created']
        arrow_obj = arrow.get(past)
        post['created'] = arrow_obj.humanize()
        result = connection.execute("""
            SELECT 1
            FROM likes
            WHERE owner = ? AND postid = ?
            LIMIT 1
        """, (logged_in_user, post["postid"])).fetchone()

        exists = result is not None
        if exists:
            post["liked"] = True
        else:
            post["liked"] = False

    context = {
        "user": logged_in_user,
        "posts": posts,
        "currentUrl": flask.request.path,
        "logged_in_user": logged_in_user
    }
    return flask.render_template("index.html", **context)


LOGGER = flask.logging.create_logger(insta485.app)


@insta485.app.route('/likes/', methods=['POST'])
def handle_likes():
    """Handle likes."""
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    LOGGER.debug("operation = %s", flask.request.form["operation"])
    LOGGER.debug("postid = %s", flask.request.form["postid"])
    operation = flask.request.form['operation']
    postid = flask.request.form['postid']
    target = flask.request.args.get('target', '/')
    connection = insta485.model.get_db()
    if operation == "like":
        # Add a like
        result = connection.execute("""
            SELECT 1
            FROM likes
            WHERE owner = ? AND postid = ?
            LIMIT 1
        """, (logged_in_user, postid)).fetchone()
        exists = result is not None
        if exists:
            # return flask.redirect(target)
            flask.abort(409)
        connection.execute(
            "INSERT INTO likes (owner, postid) VALUES (?, ?)",
            (logged_in_user, postid)
        )
    elif operation == "unlike":
        # Remove a like
        result = connection.execute("""
            SELECT 1
            FROM likes
            WHERE owner = ? AND postid = ?
            LIMIT 1
        """, (logged_in_user, postid)).fetchone()
        exists = result is not None
        if not exists:
            # return flask.redirect(target)
            flask.abort(409)
        connection.execute(
            "DELETE FROM likes WHERE owner = ? AND postid = ?",
            (logged_in_user, postid)
        )
    return flask.redirect(target)


@insta485.app.route('/comments/', methods=['POST'])
def handle_comments():
    """Handle creating a comment."""
    connection = insta485.model.get_db()
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    operation = flask.request.form['operation']
    # Not sure why this breaks delete
    postid = flask.request.form.get('postid')
    target = flask.request.args.get('target', '/')
    if operation == "create":
        text = flask.request.form['text']
        # Check if the comment text is empty
        if not text or text.strip() == '':
            flask.abort(400)  # Abort due to empty comment text

        # Insert the new comment into the database
        connection.execute(
            "INSERT INTO comments (owner, postid, text) VALUES (?, ?, ?)",
            (logged_in_user, postid, text)
        )
    elif operation == "delete":
        commentid = flask.request.form.get('commentid')
        print('delete good')
        # Verify comment ownership before deletion
        comment_query = connection.execute(
            "SELECT owner FROM comments WHERE commentid = ?",
            (commentid)
        )
        comment_owner = comment_query.fetchone()

        if comment_owner['owner'] != logged_in_user:
            flask.abort(403)  # Abort if the user doesn't own the comment

        connection.execute(
            "DELETE FROM comments WHERE commentid = ?",
            (commentid)
        )

    return flask.redirect(target)


@insta485.app.route('/uploads/<filename>')
def serve_uploaded_file(filename):
    """Serve files from sql/uploads/ dynamically."""
    if not logged_in():
        flask.abort(403)
        return flask.redirect('/accounts/login/')
    filepath = pathlib.Path(insta485.app.config["UPLOAD_FOLDER"])
    filepath = filepath / filename
    if os.path.exists(filepath):
        uploads_dir = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../var/uploads"))
    else:
        return flask.abort(404)
    return send_from_directory(uploads_dir, filename)


@insta485.app.route('/users/<user_url_slug>/')
def show_user_profile(user_url_slug):
    """Handle profile page."""
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    connection = insta485.model.get_db()
    user_query = connection.execute(
        """
        SELECT username, fullname, filename AS profile_pic
        FROM users
        WHERE username = ?
        """,
        (user_url_slug,)
    )
    user = user_query.fetchone()
    if user is None:
        flask.abort(404)  # Log this information for debugging
        # You can log this occurrence for better debugging
        print(f"User {user_url_slug} not found in database.")

    # Determine the relationship
    if logged_in_user == user_url_slug:
        relationship = ""
    else:
        follow_query = connection.execute(
            "SELECT 1 FROM following WHERE username1 = ? AND username2 = ?",
            (logged_in_user, user_url_slug)
        )
        relationship = (
            "following"
            if follow_query.fetchone()
            else "not following"
        )
    # Count posts
    posts_query = connection.execute(
        "SELECT postid, filename FROM posts WHERE owner = ?",
        (user_url_slug,)
    )
    posts = posts_query.fetchall()
    num_posts = len(posts)

    # Count followers
    followers_query = connection.execute(
        "SELECT COUNT(*) AS count FROM following WHERE username2 = ?",
        (user_url_slug,)
    )
    num_followers = followers_query.fetchone()["count"]

    # Count the users following
    following_query = connection.execute(
        "SELECT COUNT(*) AS count FROM following WHERE username1 = ?",
        (user_url_slug,)
    )
    num_following = following_query.fetchone()["count"]

    context = {
        "username": user_url_slug,
        "fullname": user["fullname"],
        "profile_pic": user["profile_pic"],
        "relationship": relationship,
        "num_posts": num_posts,
        "num_followers": num_followers,
        "num_following": num_following,
        "posts": posts,
        "logged_in_user": logged_in_user
    }

    return flask.render_template("users.html", **context)


@insta485.app.route('/users/<user_url_slug>/followers/')
def show_followers(user_url_slug):
    """Display a list of followers for a given user."""
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    connection = insta485.model.get_db()

    # Check if the given user exists
    user_query = connection.execute(
        "SELECT username FROM users WHERE username = ?",
        (user_url_slug,)
    )
    user = user_query.fetchone()

    if user is None:
        flask.abort(404)  # User not found
    # Get list of followers
    followers_query = connection.execute(
        """
        SELECT users.username, users.filename AS profile_pic
        FROM users
        JOIN following ON users.username = following.username1
        WHERE following.username2 = ?
        """,
        (user_url_slug,)
    )
    followers = followers_query.fetchall()

    followers = list(followers)

    # Determine relationship for each follower
    for follower in followers:
        if follower["username"] == logged_in_user:
            follower["relationship"] = ""
        else:
            rel_query = connection.execute(
                """
                SELECT 1
                FROM following
                WHERE username1 = ? AND username2 = ?
                """,
                (logged_in_user, follower["username"])
            )
            follower["relationship"] = (
                "following"
                if rel_query.fetchone()
                else "not following"
            )
    context = {
        "username": user_url_slug,
        "followers": followers,
        "logged_in_user": logged_in_user
    }

    return flask.render_template("followers.html", **context)


@insta485.app.route('/users/<user_url_slug>/following/')
def show_following(user_url_slug):
    """Display a list of users that <user_url_slug> is following."""
    connection = insta485.model.get_db()

    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]

    # Check if the given user exists
    user_query = connection.execute(
        "SELECT username FROM users WHERE username = ?",
        (user_url_slug,)
    )
    user = user_query.fetchone()

    if user is None:
        flask.abort(404)  # User not found

    # Get list of users this user is following
    following_query = connection.execute(
        """
        SELECT users.username, users.filename AS profile_pic
        FROM users
        JOIN following ON users.username = following.username2
        WHERE following.username1 = ?
        """,
        (user_url_slug,)
    )
    following = following_query.fetchall()
    following = list(following)
    # Determine relationship for each followed user
    for followed_user in following:
        if followed_user["username"] == logged_in_user:
            followed_user["relationship"] = ""
        else:
            rel_query = connection.execute(
                """
                SELECT 1
                FROM following
                WHERE username1 = ? AND username2 = ?
                """,
                (logged_in_user, followed_user["username"])
            )
            followed_user["relationship"] = (
                "following"
                if rel_query.fetchone()
                else "not following"
            )
    context = {
        "username": user_url_slug,
        "following": following,
        "logged_in_user": logged_in_user
    }

    return flask.render_template("following.html", **context)


@insta485.app.route('/posts/<postid_url_slug>/', methods=['GET'])
def show_post(postid_url_slug):
    """Display a specific post."""
    connection = insta485.model.get_db()

    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    # Fetch the post details
    post_query = connection.execute(
        """
        SELECT posts.postid, posts.filename, posts.owner, posts.created,
               users.fullname AS owner_fullname,
               users.filename AS owner_profile_pic,
               COUNT(likes.likeid) AS likes
        FROM posts
        LEFT JOIN likes ON posts.postid = likes.postid
        JOIN users ON posts.owner = users.username
        WHERE posts.postid = ?
        GROUP BY posts.postid
        """,
        (postid_url_slug,)
    )
    post = post_query.fetchone()

    if post is None:
        flask.abort(404)  # Post not found

    # Check if the logged in user has liked the post
    like_query = connection.execute(
        "SELECT 1 FROM likes WHERE owner = ? AND postid = ?",
        (logged_in_user, postid_url_slug)
    )
    post["liked"] = bool(like_query.fetchone())
    # Fetch comments
    comment_query = connection.execute(
        """
        SELECT comments.commentid, comments.text,
            comments.owner, users.fullname
        FROM comments
        JOIN users ON comments.owner = users.username
        WHERE comments.postid = ?
        ORDER BY comments.commentid
        """,
        (postid_url_slug,)
    )
    comments = comment_query.fetchall()

    # Format post creation time
    post['created'] = arrow.get(post['created']).humanize()

    # Determine ownership for delete button
    post['is_owner'] = post["owner"] == logged_in_user

    context = {
        "post": post,
        "comments": comments,
        "logged_in_user": logged_in_user
    }

    return flask.render_template("posts.html", **context)


@insta485.app.route('/following/', methods=['POST'])
def modify_following():
    """Follow or unfollow a user and then redirect."""
    connection = insta485.model.get_db()
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]

    # Get form data
    operation = flask.request.form.get('operation')
    username = flask.request.form.get('username')
    target = flask.request.args.get('target', '/')

    if operation == "follow":
        # Check if the logged in user already follows the target user
        follow_check = connection.execute(
            "SELECT 1 FROM following WHERE username1 = ? AND username2 = ?",
            (logged_in_user, username)
        ).fetchone()

        if follow_check:
            flask.abort(409)  # Conflict if already following

        # Add the follow relationship
        connection.execute(
            "INSERT INTO following (username1, username2) VALUES (?, ?)",
            (logged_in_user, username)
        )

    elif operation == "unfollow":
        # Check if the logged in user does not follow the target user
        unfollow_check = connection.execute(
            "SELECT 1 FROM following WHERE username1 = ? AND username2 = ?",
            (logged_in_user, username)
        ).fetchone()

        if not unfollow_check:
            flask.abort(409)  # Conflict if not following

        # Remove the follow relationship
        connection.execute(
            "DELETE FROM following WHERE username1 = ? AND username2 = ?",
            (logged_in_user, username)
        )

    return flask.redirect(target)


@insta485.app.route('/accounts/create/', methods=['GET'])
def create_account():
    """Display account creation form."""
    if logged_in():
        return flask.redirect('/accounts/edit/')
    return flask.render_template('create.html')


def create_account_function():
    """Handle account creation."""
    if logged_in():
        return flask.redirect('/accounts/edit/')

    # Get form data and file upload
    fileobj = flask.request.files['file']
    fullname = flask.request.form['fullname']
    username = flask.request.form['username']
    email = flask.request.form['email']
    password = flask.request.form['password']
    target = flask.request.args.get('target', '/')

    # Validate required fields
    if not all([fullname, username, email, password, fileobj]):
        flask.abort(400)  # Bad request

    # Generate a unique filename for the uploaded file
    uuid_stem = uuid.uuid4().hex
    file_suffix = pathlib.Path(fileobj.filename).suffix.lower()
    uuid_basename = f"{uuid_stem}{file_suffix}"
    # Save the file
    path = insta485.app.config["UPLOAD_FOLDER"] / uuid_basename
    fileobj.save(path)
    # Hash the password
    salt = uuid.uuid4().hex
    password_db_string = "$".join([
        'sha512',
        salt,
        hashlib.new('sha512', (salt + password).encode('utf-8')).hexdigest()
    ])
    # Connect to the database
    connection = insta485.model.get_db()
    # Check if the username or email already exists
    user_query = connection.execute(
        """
        SELECT 1
        FROM users
        WHERE username = ? OR email = ?
        """,
        (username, email)

    )

    if user_query.fetchone():
        flask.abort(409)  # Conflict

    # Insert the new user into the database
    connection.execute(
        """
        INSERT INTO users (username, fullname, email, filename, password)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, fullname, email, uuid_basename, password_db_string)
    )
    connection.commit()  # Save changes to the database

    # Set the username in the session
    flask.session['username'] = username
    return flask.redirect(target)  # Redirect to the target


def delete_account_function():
    """Handle account deletion."""
    if not logged_in():
        flask.abort(403)
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    target = flask.request.args.get('target', '/')

    connection = insta485.model.get_db()
    # Retrieve the user's profile image filename
    user = connection.execute(
        "SELECT filename FROM users WHERE username = ?",
        (logged_in_user,)
        ).fetchone()

    post_query = connection.execute(
        "SELECT filename FROM posts WHERE owner = ?",
        (logged_in_user,)
    ).fetchall()

    for post in post_query:
        filepath = pathlib.Path(insta485.app.config["UPLOAD_FOLDER"])
        filepath = filepath / post['filename']
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass
        connection.execute(
            "DELETE FROM comments WHERE postid = ?",
            (post['filename'],)
        )
        connection.execute(
            "DELETE FROM likes WHERE postid = ?",
            (post['filename'],)
        )
        connection.execute(
            "DELETE FROM posts WHERE filename = ?",
            (post['filename'],)
        )

    if user:
        profile_image = user['filename']
        # Delete the user from the database
        connection.execute(
            "DELETE FROM users WHERE username = ?",
            (logged_in_user,)
            )
        connection.commit()  # Commit the transaction
        # Delete the profile image from the filesystem
        if profile_image:
            filepath = pathlib.Path(insta485.app.config["UPLOAD_FOLDER"])
            filepath = filepath / profile_image
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass  # File might already be gone, continue
        del flask.session['username']
    return flask.redirect(target)


def edit_account_function():
    """Handle editing the account."""
    if not logged_in():
        flask.abort(403)
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    target = flask.request.args.get('target', '/')
    connection = insta485.model.get_db()

    fileobj = flask.request.files['file']
    filename = fileobj.filename
    fullname = flask.request.form['fullname']
    email = flask.request.form['email']

    if not all([fullname, email]):
        flask.abort(400)

    if fileobj:
        # Save the new profile image
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)

    connection.execute(
        """
        UPDATE users
        SET fullname = ?, email = ?, filename = ?
        WHERE username = ?
        """,
        (fullname, email, uuid_basename, logged_in_user)
    )

    return flask.redirect(target)


def update_password_function():
    """Handle updating the password."""
    if not logged_in():
        flask.abort(403)
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    target = flask.request.args.get('target', '/')
    connection = insta485.model.get_db()
    current_password = flask.request.form['password']
    new_password = flask.request.form['new_password1']
    new_password_confirm = flask.request.form['new_password2']

    if not all([current_password, new_password, new_password_confirm]):
        flask.abort(400)

    # Hash the current password for comparison
    user_query = connection.execute(
        "SELECT password FROM users WHERE username = ?",
        (logged_in_user,)
    ).fetchone()

    if user_query is None:
        return flask.redirect(flask.url_for("/"))

    password_db_string = user_query['password']
    algorithm, salt, password_hash = password_db_string.split('$')
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + current_password
    hash_obj.update(password_salted.encode('utf-8'))
    current_password_hash = hash_obj.hexdigest()

    if current_password_hash != password_hash:
        flask.abort(403)
        return flask.redirect(target)

    # Hash the new password for storage
    if new_password != new_password_confirm:
        flask.abort(401)
        return flask.redirect(target)
    algorithm = 'sha512'
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + new_password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])

    # Update the password in the database
    connection.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (password_db_string, logged_in_user)
    )

    connection.commit()  # Commit the transaction
    return flask.redirect(target)


def login_function():
    """Handle user login."""
    if logged_in():
        return flask.redirect('/')
    username = flask.request.form['username']
    password = flask.request.form['password']
    if not username or not password:
        flask.abort(400)
    target = flask.request.args.get('target', '/')
    connection = insta485.model.get_db()
    # Hash the password for comparison
    user_query = connection.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user_query is None:
        return flask.abort(403)

    password_db_string = user_query['password']
    algorithm, salt, stored_hash = password_db_string.split('$')
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    computed_hash = hash_obj.hexdigest()

    if computed_hash != stored_hash:
        flask.abort(403)
        return flask.redirect("/accounts/login/")

    flask.session['username'] = username

    return flask.redirect(target)


@insta485.app.route('/accounts/', methods=['POST'])
def account_functions():
    """Handle creation of account."""
    operation = flask.request.form['operation']
    if operation == 'create':
        return create_account_function()
    if operation == 'delete':
        return delete_account_function()
    if operation == 'edit_account':
        return edit_account_function()
    if operation == 'update_password':
        return update_password_function()
    if operation == 'login':
        return login_function()

    return flask.render_template('create.html')


@insta485.app.route('/explore/')
def explore_users():
    """Display a list of users not followed by the logged-in user."""
    connection = insta485.model.get_db()

    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]
    # Query to find users that the logged-in user is not following
    explore_query = connection.execute(
        """
        SELECT users.username, users.fullname, users.filename AS profile_pic
        FROM users
        WHERE username != ?
        AND username NOT IN (
            SELECT username2 FROM following WHERE username1 = ?
        )
        """,
        (logged_in_user, logged_in_user)
    )
    unfollowed_users = explore_query.fetchall()
    context = {
        "unfollowed_users": unfollowed_users,
        "logged_in_user": logged_in_user
    }

    return flask.render_template("explore.html", **context)


@insta485.app.route('/accounts/edit/')
def edit_account():
    """Display edit account page."""
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session.get("username")
    connection = insta485.model.get_db()
    # Fetch current user's information
    user_query = connection.execute(
        "SELECT username, fullname, email, filename \
        AS profile_pic FROM users WHERE username = ?",
        (logged_in_user,)
    )
    user = user_query.fetchone()

    if user is None:
        flask.abort(404)

    context = {
        "user": user,
        "logged_in_user": logged_in_user,
    }

    return flask.render_template("edit_account.html", **context)


@insta485.app.route('/accounts/delete/')
def delete_account():
    """Display the delete account confirmation page."""
    connection = insta485.model.get_db()

    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]

    # Fetch current user's information
    user_query = connection.execute(
        "SELECT username FROM users WHERE username = ?",
        (logged_in_user,)
    )
    user = user_query.fetchone()

    if user is None:
        flask.abort(404)  # User not found

    context = {
        "username": user["username"],
        "logged_in_user": logged_in_user
    }

    return flask.render_template("delete_account.html", **context)


@insta485.app.route('/accounts/password/')
def change_password():
    """Display the change password page."""
    connection = insta485.model.get_db()

    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session["username"]

    # Fetch current user's information
    user_query = connection.execute(
        "SELECT username FROM users WHERE username = ?",
        (logged_in_user,)
    )
    user = user_query.fetchone()

    if user is None:
        flask.abort(404)  # User not found

    context = {
        "username": user["username"],
        "logged_in_user": logged_in_user
    }

    return flask.render_template("pw_account.html", **context)


@insta485.app.route('/accounts/auth/')
def authenticate_user():
    """Authenticate user session. Return 200 if logged in, 403 if not."""
    # Check for logged-in status. This typically means checking session data.
    if 'username' in flask.session:
        # Return a 200 status code with no content
        return '', 200

    # Abort with a 403 Forbidden status if not logged in
    flask.abort(403)


@insta485.app.route('/accounts/login/')
def login():
    """Display the login page or redirect if already logged in."""
    # Check if the user is logged in
    if 'username' in flask.session:
        return flask.redirect('/')

    # If not logged in, render the login page
    return flask.render_template("login.html")


@insta485.app.route('/posts/', methods=['POST'])
def handle_posts():
    """Create or delete a post based on the POST request, then redirect."""
    connection = insta485.model.get_db()
    if not logged_in():
        return flask.redirect('/accounts/login/')

    logged_in_user = flask.session.get("username")

    # Extract parameters from the form data
    operation = flask.request.form.get('operation')
    postid = flask.request.form.get('postid')
    target = flask.request.args.get('target', f"/users/{logged_in_user}/")

    if operation == "create":
        # Attempt to retrieve the file from the form data
        fileobj = flask.request.files["file"]
        filename = fileobj.filename

        # Check for an empty file submission
        if not fileobj or not filename:
            flask.abort(400)  # Abort with a 400 Bad Request code

        # Generate a unique filename using a UUID
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"
        # Define file path and save the file
        path = pathlib.Path(insta485.app.config["UPLOAD_FOLDER"])
        path = path / uuid_basename
        fileobj.save(path)
        # Insert new post record into the database
        connection.execute(
            "INSERT INTO posts (owner, filename) VALUES (?, ?)",
            (logged_in_user, uuid_basename)
        )

    elif operation == "delete":
        # Retrieve post details and ensure user ownership
        post_query = connection.execute(
            "SELECT owner, filename FROM posts WHERE postid = ?",
            (postid,)
        )
        post = post_query.fetchone()

        if post["owner"] != logged_in_user:
            flask.abort(403)  # Abort if user does not own the post

        # Remove file from filesystem
        filepath = pathlib.Path(insta485.app.config["UPLOAD_FOLDER"])
        filepath = filepath / post["filename"]

        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass  # File might already be gone, continue

        # Clean up database entries related to the post
        connection.execute("DELETE FROM posts WHERE postid = ?", (postid,))
        connection.execute("DELETE FROM comments WHERE postid = ?", (postid,))
        connection.execute("DELETE FROM likes WHERE postid = ?", (postid,))

    # Redirect to the provided target URL or to the user's profile by default
    return flask.redirect(target)


@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout():
    """Logout the user."""
    # Clear the session data
    flask.session.clear()
    return flask.redirect('/accounts/login/')

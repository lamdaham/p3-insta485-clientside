"""REST API for posts."""
import flask
import insta485
import hashlib

@insta485.app.route('/api/v1/', methods=['GET'])
def get_api():
    """Return service metadata."""
    context = {
        "comments": "/api/v1/comments/",
        "likes": "/api/v1/likes/",
        "posts": "/api/v1/posts/",
        "url": "/api/v1/"
    }
    return flask.jsonify(**context)

@insta485.app.route('/api/v1/posts/', methods=['GET'])
def get_posts():
    """Return a paginated list of posts."""
    auth = flask.request.authorization
    if auth is None and "username" not in flask.session:
        return flask.jsonify({}), 403

    # Get the username from session or auth
    if "username" in flask.session:
        username = flask.session["username"]
    else:
        username = auth.get("username")
        password = auth.get("password")
        # Verify credentials if provided.
        connection = insta485.model.get_db()
        user_query = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        if user_query is None:
            return flask.jsonify({}), 401
        password_db_string = user_query["password"]
        algorithm, salt, hash_val = password_db_string.split("$")
        hash_obj = hashlib.new(algorithm)
        hash_obj.update((salt + password).encode("utf-8"))
        if hash_obj.hexdigest() != hash_val:
            return flask.jsonify({}), 401
        flask.session["username"] = username

    # Now we have a logged‐in username.
    connection = insta485.model.get_db()

    # Get pagination parameters.
    size = flask.request.args.get("size", default=10, type=int)
    page = flask.request.args.get("page", default=0, type=int)
    postid_lte = flask.request.args.get("postid_lte", type=int)

    if size is None or size <= 0 or page is None or page < 0:
        return flask.jsonify(message="Bad Request", status_code=400), 400

    # If no postid_lte is given, set it to the most recent (i.e. maximum) postid
    if postid_lte is None:
        max_post_query = connection.execute(
            """
            SELECT MAX(postid) AS max_postid
            FROM posts
            WHERE (owner = :username OR owner IN (
                      SELECT username2 FROM following WHERE username1 = :username
                  ))
            """,
            {"username": username}
        ).fetchone()
        if max_post_query and max_post_query["max_postid"] is not None:
            postid_lte = max_post_query["max_postid"]
        else:
            postid_lte = 0

    offset = page * size
    posts_query = connection.execute(
        """
        SELECT postid
        FROM posts
        WHERE (owner = :username OR owner IN (
                  SELECT username2 FROM following WHERE username1 = :username
              ))
          AND postid <= :postid_lte
        ORDER BY postid DESC
        LIMIT :limit OFFSET :offset;
        """,
        {
            "username": username,
            "postid_lte": postid_lte,
            "limit": size,
            "offset": offset,
        }
    ).fetchall()

    results = []
    for row in posts_query:
        results.append({
            "postid": row["postid"],
            "url": f"/api/v1/posts/{row['postid']}/"
        })

    # Set next URL if exactly 'size' posts were returned.
    if len(results) == size:
        next_url = flask.url_for(
            "get_posts",
            size=size,
            page=page + 1,
            postid_lte=postid_lte,
            _external=False
        )
    else:
        next_url = ""

    # Build a relative "url" field based on the request path and query string.
    if flask.request.query_string:
        qs = flask.request.query_string.decode("utf-8")
        req_url = flask.request.path + "?" + qs
    else:
        req_url = flask.request.path

    context = {
        "next": next_url,
        "results": results,
        "url": req_url
    }
    return flask.jsonify(**context)


@insta485.app.route('/api/v1/posts/<int:postid>/', methods=['GET'])
def get_post_detail(postid):
    """Return detailed information about a specific post."""
    # Require authentication.
    auth = flask.request.authorization
    if auth is None and "username" not in flask.session:
        return flask.jsonify({}), 403

    username = flask.session.get("username")
    if not username:
        username = auth.get("username")
        # (Assume credentials have been checked already.)
        flask.session["username"] = username

    connection = insta485.model.get_db()

    # Get the post.
    post = connection.execute(
        "SELECT postid, filename, owner, created FROM posts WHERE postid = ?",
        (postid,)
    ).fetchone()
    if post is None:
        flask.abort(404)

    # Get the owner's image filename.
    owner_user = connection.execute(
        "SELECT filename FROM users WHERE username = ?",
        (post["owner"],)
    ).fetchone()
    owner_filename = owner_user["filename"] if owner_user else ""

    # Compute URLs.
    imgUrl = f"/uploads/{post['filename']}"
    postShowUrl = f"/posts/{postid}/"
    self_url = f"/api/v1/posts/{postid}/"

    # Query comments for this post.
    comments_rows = connection.execute(
        "SELECT commentid, owner, text FROM comments WHERE postid = ? ORDER BY commentid ASC",
        (postid,)
    ).fetchall()
    comments = []
    for row in comments_rows:
        comments.append({
            "commentid": row["commentid"],
            "owner": row["owner"],
            "text": row["text"],
            "url": f"/api/v1/comments/{row['commentid']}/",
            "ownerShowUrl": f"/users/{row['owner']}/",
            "lognameOwnsThis": (row["owner"] == username)
        })
    comments_url = f"/api/v1/comments/?postid={postid}"

    # Query likes: count them and check if the logged‐in user liked this post.
    like_count_row = connection.execute(
        "SELECT COUNT(*) AS count FROM likes WHERE postid = ?",
        (postid,)
    ).fetchone()
    numLikes = like_count_row["count"] if like_count_row else 0

    like_row = connection.execute(
        "SELECT likeid FROM likes WHERE postid = ? AND owner = ?",
        (postid, username)
    ).fetchone()
    if like_row:
        lognameLikesThis = True
        like_url = f"/api/v1/likes/{like_row['likeid']}/"
    else:
        lognameLikesThis = False
        like_url = None

    likes = {
        "numLikes": numLikes,
        "lognameLikesThis": lognameLikesThis,
        "url": like_url
    }

    # Build the response dictionary.
    response = {
        "postid": post["postid"],
        "owner": post["owner"],
        "created": post["created"],
        "imgUrl": imgUrl,
        "url": self_url,
        "comments": comments,
        "comments_url": comments_url,
        "likes": likes,
        "ownerImgUrl": f"/uploads/{owner_filename}",
        "ownerShowUrl": f"/users/{post['owner']}/",
        "postShowUrl": postShowUrl
    }
    return flask.jsonify(response)

@insta485.app.route('/api/v1/likes/', methods=['POST'])
def create_like():
    """Create one “like” for a specific post.

    Returns 201 CREATED if a new like is created.
    Returns 200 OK if the like already exists.
    Returns 404 if the post does not exist.
    """
    import hashlib

    # Require authentication.
    auth = flask.request.authorization
    if auth is None and "username" not in flask.session:
        return flask.jsonify({}), 403

    # Get username from session or verify credentials.
    if "username" in flask.session:
        username = flask.session["username"]
    else:
        username = auth.get("username")
        password = auth.get("password")
        connection = insta485.model.get_db()
        user_query = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        if user_query is None:
            return flask.jsonify({}), 401
        password_db_string = user_query["password"]
        algorithm, salt, hash_val = password_db_string.split("$")
        hash_obj = hashlib.new(algorithm)
        hash_obj.update((salt + password).encode("utf-8"))
        if hash_obj.hexdigest() != hash_val:
            return flask.jsonify({}), 401
        flask.session["username"] = username

    connection = insta485.model.get_db()

    # Get postid from the query string.
    postid = flask.request.args.get("postid", type=int)
    if postid is None:
        # If no postid is given, or it is invalid, return a 404.
        flask.abort(404)

    # Check that the post exists.
    post = connection.execute(
        "SELECT postid FROM posts WHERE postid = ?",
        (postid,)
    ).fetchone()
    if post is None:
        flask.abort(404)

    # Check if a like by this user on this post already exists.
    like = connection.execute(
        "SELECT likeid FROM likes WHERE postid = ? AND owner = ?",
        (postid, username)
    ).fetchone()

    if like is not None:
        # The like already exists: return it with a 200 OK.
        response = {
            "likeid": like["likeid"],
            "url": f"/api/v1/likes/{like['likeid']}/"
        }
        return flask.jsonify(response), 200

    # Otherwise, create a new like.
    connection.execute(
        "INSERT INTO likes (owner, postid) VALUES (?, ?)",
        (username, postid)
    )
    connection.commit()

    # Retrieve the new likeid. (This method works for SQLite.)
    new_like = connection.execute(
        "SELECT last_insert_rowid() AS id"
    ).fetchone()
    likeid = new_like["id"]

    response = {
        "likeid": likeid,
        "url": f"/api/v1/likes/{likeid}/"
    }
    return flask.jsonify(response), 201

@insta485.app.route('/api/v1/likes/<int:likeid>/', methods=['DELETE'])
def delete_like(likeid):
    """Delete a like.
    
    Returns 204 NO CONTENT on success.
    Returns 404 if the like does not exist.
    Returns 403 if the user does not own the like.
    """
    # Require authentication
    auth = flask.request.authorization
    if auth is None and "username" not in flask.session:
        return flask.jsonify({}), 403  # ✅ Remove "url": None, use an empty JSON

    # Get username from session or verify credentials
    if "username" in flask.session:
        username = flask.session["username"]
    else:
        username = auth.get("username")
        password = auth.get("password")
        connection = insta485.model.get_db()
        user_query = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        if user_query is None:
            return flask.jsonify({}), 401
        password_db_string = user_query["password"]
        algorithm, salt, hash_val = password_db_string.split("$")
        hash_obj = hashlib.new(algorithm)
        hash_obj.update((salt + password).encode("utf-8"))
        if hash_obj.hexdigest() != hash_val:
            return flask.jsonify({}), 401
        flask.session["username"] = username

    connection = insta485.model.get_db()

    # Check if the like exists
    like = connection.execute(
        "SELECT owner FROM likes WHERE likeid = ?",
        (likeid,)
    ).fetchone()

    if like is None:
        # Like does not exist, return 404
        flask.abort(404)

    # Check if the user owns the like
    if like["owner"] != username:
        # User does not own the like, return 403
        flask.abort(403)

    # Delete the like
    connection.execute(
        "DELETE FROM likes WHERE likeid = ?",
        (likeid,)
    )
    connection.commit()

    return "", 204  # ✅ Ensure no JSON response, only status code 204

@insta485.app.route('/api/v1/comments/', methods=['POST'])
def add_comment():
    """Add a comment to a post.

    Returns:
        201 Created on success.
        400 Bad Request if comment text is missing.
        403 Forbidden if user is not authenticated.
        404 Not Found if postid does not exist.
    """
    # Require authentication
    auth = flask.request.authorization
    if auth is None and "username" not in flask.session:
        return flask.jsonify({}), 403

    # Get username from session or verify credentials
    if "username" in flask.session:
        username = flask.session["username"]
    else:
        username = auth.get("username")
        password = auth.get("password")
        connection = insta485.model.get_db()
        user_query = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user_query is None:
            return flask.jsonify({}), 401
        password_db_string = user_query["password"]
        algorithm, salt, hash_val = password_db_string.split("$")
        hash_obj = hashlib.new(algorithm)
        hash_obj.update((salt + password).encode("utf-8"))
        if hash_obj.hexdigest() != hash_val:
            return flask.jsonify({}), 401
        flask.session["username"] = username

    connection = insta485.model.get_db()

    # Get post ID from query parameters
    postid = flask.request.args.get("postid", type=int)
    if postid is None:
        return flask.jsonify({"message": "Missing postid"}), 404

    # Ensure the post exists
    post = connection.execute(
        "SELECT postid FROM posts WHERE postid = ?", (postid,)
    ).fetchone()
    if post is None:
        return flask.jsonify({"message": "Post not found"}), 404

    # Get comment text from request JSON
    comment_json = flask.request.get_json()
    if not comment_json or "text" not in comment_json:
        return flask.jsonify({"message": "Missing comment text"}), 400
    text = comment_json["text"].strip()
    
    if not text:
        return flask.jsonify({"message": "Comment text cannot be empty"}), 400

    # Insert comment into the database
    connection.execute(
        "INSERT INTO comments (owner, postid, text) VALUES (?, ?, ?)",
        (username, postid, text)
    )
    connection.commit()

    # Retrieve the new comment ID
    new_comment = connection.execute("SELECT last_insert_rowid() AS id").fetchone()
    commentid = new_comment["id"]

    # Construct response
    response = {
        "commentid": commentid,
        "lognameOwnsThis": True,
        "owner": username,
        "ownerShowUrl": f"/users/{username}/",
        "text": text,
        "url": f"/api/v1/comments/{commentid}/"
    }

    return flask.jsonify(response), 201

@insta485.app.route('/api/v1/comments/<int:commentid>/', methods=['DELETE'])
def delete_comment(commentid):
    """Delete a comment.

    Returns:
        204 No Content on success.
        403 Forbidden if user does not own the comment.
        404 Not Found if comment does not exist.
    """
    # Require authentication
    auth = flask.request.authorization
    if auth is None and "username" not in flask.session:
        return flask.jsonify({}), 403

    # Get username from session or verify credentials
    if "username" in flask.session:
        username = flask.session["username"]
    else:
        username = auth.get("username")
        password = auth.get("password")
        connection = insta485.model.get_db()
        user_query = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user_query is None:
            return flask.jsonify({}), 401
        password_db_string = user_query["password"]
        algorithm, salt, hash_val = password_db_string.split("$")
        hash_obj = hashlib.new(algorithm)
        hash_obj.update((salt + password).encode("utf-8"))
        if hash_obj.hexdigest() != hash_val:
            return flask.jsonify({}), 401
        flask.session["username"] = username

    connection = insta485.model.get_db()

    # Check if the comment exists
    comment = connection.execute(
        "SELECT owner FROM comments WHERE commentid = ?", (commentid,)
    ).fetchone()

    if comment is None:
        # Comment does not exist, return 404
        flask.abort(404)

    # Check if the user owns the comment
    if comment["owner"] != username:
        # User does not own the comment, return 403
        flask.abort(403)

    # Delete the comment
    connection.execute(
        "DELETE FROM comments WHERE commentid = ?", (commentid,)
    )
    connection.commit()

    return "", 204  # No content response
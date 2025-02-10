PRAGMA foreign_keys = ON;

CREATE TABLE users (
    username TEXT NOT NULL
        CHECK (LENGTH(username) <= 20)
        PRIMARY KEY,
    fullname TEXT NOT NULL
        CHECK (LENGTH(fullname) <= 40),
    email TEXT NOT NULL
        CHECK (LENGTH(email) <= 40),
    filename TEXT NOT NULL
        CHECK (LENGTH(filename) <= 64),
    password TEXT NOT NULL
        CHECK (LENGTH(password) <= 256),
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    postid INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL
        CHECK (LENGTH(filename) <= 64),
    owner TEXT NOT NULL
        CHECK (LENGTH(owner) <= 20),
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner)
        REFERENCES users(username)
        ON DELETE CASCADE
);


CREATE TABLE following (
    username1 TEXT NOT NULL
        CHECK (LENGTH(username1) <= 20),
    username2 TEXT NOT NULL
        CHECK (LENGTH(username2) <= 20),
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (username1, username2),
    FOREIGN KEY (username1)
        REFERENCES users(username)
        ON DELETE CASCADE,
    FOREIGN KEY (username2)
        REFERENCES users(username)
        ON DELETE CASCADE
);

CREATE TABLE comments (
    commentid INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL
        CHECK (LENGTH(owner) <= 20),
    postid INTEGER NOT NULL,
    text TEXT NOT NULL
        CHECK (LENGTH(text) <= 1024),
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner)
        REFERENCES users(username)
        ON DELETE CASCADE,
    FOREIGN KEY (postid)
        REFERENCES posts(postid)
        ON DELETE CASCADE
);


CREATE TABLE likes (
    likeid INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL
        CHECK (LENGTH(owner) <= 20),
    postid INTEGER NOT NULL,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner)
        REFERENCES users(username)
        ON DELETE CASCADE,
    FOREIGN KEY (postid)
        REFERENCES posts(postid)
        ON DELETE CASCADE
);
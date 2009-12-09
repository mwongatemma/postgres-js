# PostgreSQL for Javascript

This library is a implementation of the PostgreSQL backend/frontend protocol in javascript.
It uses the node.js tcp and event libraries.  A javascript md5 library is included for servers that require md5 password hashing (this is default).

This library also allows for the handling of prepared queries and parameterized queries. 

## Example use

	var sys = require("sys");
	var Postgres = require("./postgres");

	var db = new Postgres.Connection("database", "username", "password");
	db.query("SELECT * FROM sometable", function (data) {
		sys.p(data);
	});
	db.close();

## Example use of Parameterized Queries

    var sys = require("sys");
    var pg = require("postgres.js");
    
    var db = new pg.Connection("database", "username", "password");
    db.query("SELECT * FROM yourtable WHERE id = ?", [1], function (data) {
        
        sys.p(data);
    });
    db.close();

## Example use of Prepared Queries

    var sys = require("sys");
    var pg = require("postgres.js");
    
    var db = new pg.Connection("database", "username", "password");
    
    db.prepare("SELECT * FROM yourtable WHERE id = ?").addCallback( function (query) {

        sys.p(query);
        query.execute(["1"], function (d) {
            sys.p(d);
        });
        /* More queries here. */
    });
    db.close();
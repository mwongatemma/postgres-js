# PostgreSQL for Javascript

This library is a implementation of the PostgreSQL backend/frontend protocol in javascript.
It uses the node.js tcp and event libraries.  A javascript md5 library is included for servers that require md5 password hashing (this is default).

This library allows for the correct handling of prepared queries.

If you wish to nest DB calls, db.close must be in the deepest callback, or all statements that occur inside of callbacks deeper than the callback which handles db.close will not be executed.

All code is available under the terms of the MIT license, unless otherwise noted (md5.js)

## Example use

	var sys = require("sys");
	var pg = require("postgres");

    var db = new pg.connect("pgsql://test:12345@localhost:5432/template1");
	db.query("SELECT * FROM sometable", function (data) {
		sys.p(data);
	});
	db.close();

## Example use of Parameterized Queries

    var sys = require("sys");
    var pg = require("postgres");
    
    var db = new pg.connect("pgsql://test:12345@localhost:5432/template1");
    db.query("SELECT * FROM yourtable WHERE id = ?", [1], function (data) {
        sys.p(data);
    });
    db.close();

## Example use of Prepared Queries

    var sys = require("sys");
    var pg = require("postgres");
    
    var db = new pg.connect("pgsql://test:12345@localhost:5432/template1");
    
    var stmt = db.prepare("SELECT * FROM yourtable WHERE id = ?");
    
    stmt.execute([1], function (d) {
        sys.p(d);
        db.close();
    });
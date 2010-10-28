var sys = require("sys");
var pg = require("./lib/postgres-pure");
// pg.DEBUG=4;

var db = new pg.connect("pgsql://test:12345@localhost:5432/returning_test");
db.query("SELECT 1::querytest;", function (error, rs, tx) {
    if (error) {
        console.log("Error!");
        sys.puts(error);
        sys.puts(error.code);
    }
    else {
        sys.puts(sys.inspect(rs));
    }
    
    // tx.query("SELECT 2::int as querytest2", function (rs) {
    //     sys.puts(sys.inspect(rs));
    // });
});

db.prepare("INSERT INTO returning_test (val) VALUES (?) RETURNING id, val", function (sth) {
    sth.execute("text value", function(e, rs) {
        if (rs === undefined) {
            console.log("No data.");
        }
        else {
            console.log(sys.inspect(rs));
        }
    });
});

// db.prepare().on("some_event"); 

// db.prepare("SELECT ?::int AS preparetest", function (sth, tx) {
//     sth.execute(1, function (rs) {
//         sys.puts(sys.inspect(rs));
//     });
//     sth.execute(2, function (rs) {
//         sys.puts(sys.inspect(rs));
//         
//     });
//     // tx.prepare("SELECT ?::int AS preparetest2", function (sth) {
//     //    sth.execute(3, function (rs) {
//     //        sys.puts(sys.inspect(rs));
//     //    }) ;
//     // });
// });

// db.transaction(function (tx) {
//     // tx.begin();
//     tx.query("SELECT ?::int AS txtest1", 1, function (rs) {
//         sys.puts(sys.inspect(rs));
//     });
//     tx.prepare("SELECT ?::int AS txtest2", function (sth) {
//         sth.execute(2, function (rs) {
//             sys.puts(sys.inspect(rs));
//         });
//     });
//     // tx.commit();
// });
db.close();

// db.prepare(query, function (sth, tx) {
//     sth.execute(args, callback, errback);
// })
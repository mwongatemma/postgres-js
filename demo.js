var sys = require("sys");
var pg = require("./lib/postgres-pure");
pg.DEBUG=0;

var db = new pg.connect("pgsql://test:12345@localhost:5432/template1");
db.query("SELECT 1::int as foobar;", function (rs, tx) {
    sys.puts(sys.inspect(rs));
    tx.query("SELECT 2::int as foobartwo", function (rs) {
        sys.puts(sys.inspect(rs));
    });
    // db.close();
});

db.prepare("SELECT ?::int AS foobar", function (sth, tx) {
    sth.execute(1, function (rs) {
        sys.puts(sys.inspect(rs));
    });
    sth.execute(2, function (rs) {
        sys.puts(sys.inspect(rs));
        
    });
    tx.prepare("SELECT ?::int AS cheese", function (sth) {
       sth.execute(3, function (rs) {
           sys.puts(sys.inspect(rs));
       }) ;
    });
    // db.close();
});

db.transaction(function (tx) {
    // tx.begin();
    tx.query("SELECT ?::int AS txtest1", 1, function (rs) {
        sys.puts(sys.inspect(rs));
    });
    tx.prepare("SELECT ?::int AS txtest2", function (sth) {
        sth.execute(2, function (rs) {
            sys.puts(sys.inspect(rs));
        });
    });
    // tx.commit();
});

db.close();
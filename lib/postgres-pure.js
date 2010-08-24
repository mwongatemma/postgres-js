/*
Copyright (c) 2010 Tim Caswell <tim@creationix.com>,
          (c) 2010 Aurynn Shaw <ashaw@commandprompt.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


var md5 = require('./md5');
var net = require("net");
var sys = require("sys");
var url = require('url');
var Buffer = require('./buffer_extras');

exports.DEBUG = 0;

function encoder(header) {
  header = header || "";
  var w = Buffer.makeWriter();
  w.frame = function frame() {
    var message = w.toBuffer();
    var buffer = new Buffer(message.length + 4 + header.length);
    var offset = 0;
    if (header.length > 0) {
      buffer.write(header, 'ascii', offset);
      offset += header.length;
    }
    buffer.int32Write(message.length + 4, offset);
    offset += 4;
    message.copy(buffer, offset);
    return buffer;
  }
  return w;
}

// http://www.postgresql.org/docs/8.3/static/protocol-message-formats.html
var formatter = {
  Bind: function (portal, prepared_name, params, args) {
      var builder =  (encoder('B'))
        .push.cstring(portal)
        .push.cstring(prepared_name)
        .push.int16(args.length); // declare our format codes as expected.
      
      for (var i = 0; i < args.length; i++) {
          switch (typeof args[i]) {
              case "number":
              case "boolean":
              case "object":
                builder.push.int16(1); // binary
                break;
              case "string":
                builder.push.int16(0);
                break;
          }
      }
      
      builder.push.int16(args.length);
      for (var i = 0; i < args.length; i++) {
          switch (typeof args[i]) {
              case "number":
                builder.push.int32(4) // 4 bytes. int32.
                    .push.int32(args[i]);
                break;
              case "string":
                builder.push.int32(args[i].length)
                    .push.string(args[i]); // Not a cstring. Don't \0
                break;
              case "boolean":
                builder.push.int32(1) // One byte.
                    .push.string(args[i] ? 1 : 0);
                break;
              case "object":
                if (args[i] === null) {
                    builder.push.int32(-1);
                }
          };
      }
      builder.push.int16(0); // They should all use text. Don't declare return
                             // types, as we already have the types from the
                             // ParameterDescription
      return builder;
  },
  CopyData: function () {
    // TODO: implement
  },
  CopyDone: function () {
    // TODO: implement
  },
  Describe: function (type, name) {
    return (encoder('D'))
      .push.byte1(type) // Byte string aka ascii.
      .push.cstring(name);
  },
  Execute: function (name, max_rows) {
    return (encoder('E'))
      .push.cstring(name)
      .push.int32(max_rows);
  },
  Flush: function () {
    return encoder('H');
  },
  FunctionCall: function () {
    // TODO: implement
  },
  Parse: function (name, query, var_types) {
    var builder = (encoder('P'))
      .push.cstring(name)
      .push.cstring(query)
      .push.int16(var_types.length);
    for (var i = 0; i < var_types.length; i++) {
        builder.push.int32(var_types[i]);
    }
    // var_types.each(function (var_type) {
    //   builder.push.int32(var_type);
    // });
    return builder;
  },
  PasswordMessage: function (password) {
    return (encoder('p'))
      .push.cstring(password);
  },
  Query: function (query) {
    return (encoder('Q'))
      .push.cstring(query);
  },
  SSLRequest: function () {
    return (encoder())
      .push.int32(0x4D2162F);
  },
  StartupMessage: function (options) {
    // Protocol version number 3
    return encoder()
      .push.int32(0x30000)
      .push.hash(options);
  },
  Sync: function () {
    return encoder('S');
  },
  Terminate: function () {
    return encoder('X');
  }
};

// Parse response streams from the server
function parse_response(code, buffer) {
  var input, type, args, num_fields, data, size, i;
  reader = buffer.toReader();
  args = [];
  switch (code) {
  case 'R':
    switch (reader.int32()) {
    case 0:
      type = "AuthenticationOk";
      break;
    case 2:
      type = "AuthenticationKerberosV5";
      break;
    case 3:
      type = "AuthenticationCleartextPassword";
      break;
    case 4:
      type = "AuthenticationCryptPassword";
      args = [reader.string(2)];
      break;
    case 5:
      type = "AuthenticationMD5Password";
      args = [reader.buffer(4)];
      break;
    case 6:
      type = "AuthenticationSCMCredential";
      break;
    case 7:
      type = "AuthenticationGSS";
      break;
    case 8:
      // TODO: add in AuthenticationGSSContinue
      type = "AuthenticationSSPI";
      break;
    default:
    
      break;
    }
    break;
  case 'E':
    type = "ErrorResponse";
    args = [{}];
    reader.multicstring().forEach(function (field) {
      args[0][field[0]] = field.substr(1);
    });
    break;
  case 't':
    type = "ParameterDescription",
    num_fields = reader.int16();
    data = [];
    for (var i = 0; i < num_fields; i++) {
        data.push(reader.int32());
    }
    args = [data];
    break;
  case 'S':
    type = "ParameterStatus";
    args = [reader.cstring(), reader.cstring()];
    break;
  case 'K':
    type = "BackendKeyData";
    args = [reader.int32(), reader.int32()];
    break;
  case 'Z':
    type = "ReadyForQuery";
    args = [reader.string(1)];
    break;
  case 'T':
    type = "RowDescription";
    num_fields = reader.int16();
    data = [];
    for (var i = 0; i < num_fields; i += 1) {
        data.push({
            field: reader.cstring(),
            table_id: reader.int32(),
            column_id: reader.int16(),
            type_id: reader.int32(),
            type_size: reader.int16(),
            type_modifier: reader.int32(),
            format_code: reader.int16()
        });
    }
    args = [data];
    break;
  case 'D':
    type = "DataRow";
    data = [];
    num_fields = reader.int16();
    for (i = 0; i < num_fields; i += 1) {
      size = reader.int32();
      if (size === -1) {
        data.push(null);
      } else {
        data.push(reader.string(size));
      }
    }
    args = [data];
    break;
  case 'C':
    type = "CommandComplete";
    args = [reader.cstring()];
    break;
  case 'N':
    type = "NoticeResponse";
    args = [{}];
    reader.multicstring().forEach(function (field) {
      args[0][field[0]] = field.substr(1);
    });
    break;
  case '1':
    type = 'ParseComplete';
    args = [{}];
    break;
  case 'n':
    type = 'NoData';
    args = [];
    break;
  }
  
  if (!type) {
    sys.debug("Unknown response " + code);  
  }
  return {type: type, args: args};
}


function Query(sql, callback) {
    this.sql = sql;
    var q = this;
    var row_description, results;
    results = [];
    /* 
    Returns the next query object in this object buffer.
    This can be null.
    */
    var arr = [
        {
            type: 'Query',
            args: [sql]
        },
        {
            type: 'Flush',
            args: []
        }
    ];
    var arrpos = 0;
    q.next = function () {
        arrpos += 1;
        return arr[arrpos-1];
    };
    
    q.addListener("RowDescription", function (desc) {
        row_description = desc;
    });
    q.addListener("newRow", function (row) {
        results.push(row);
    });
    q.addListener("Complete", function (data) {
        callback(results);
    });
}

Query.prototype = new process.EventEmitter;

function Prepared(sql, conn, callback) {
    
    var prepared_name = md5(sql); // Use the md5 hash. This is easily selectable later.
    var q = this;
    var portal = 'meh';
    q.row_description = null;
    q.param_description = null;
    q.noData = false;
    
    var parseComplete = null;
    var readyToExec = false;
    var conn = conn;
    
    var pos = 0;
    var callback = callback;
    var arr = [
        {
            type: "Parse",
            // Prepared name, the query, and a zero-length array to declare no types.
            args: [prepared_name, sql, []], 
        },
        {
            type: "Describe",
            args: ["S", prepared_name],
        },
        {
            type: "Flush",
            args: [],
        },
    ]; // This describes a (nearly) complete lifecycle of a prepared statement.
    
    q.addListener("ParseComplete", function () {
        // Execute can now be run successfully.
        // Until this point, we can't assume that there's a matching query.
        // Anyway, we now run a DESCRIBE operation, and store the row 
        // description in our object.
        // Later optimization might hold on to these objects as hashes in the
        // connection object.
        // conn.next();
        parseComplete = true;
        q.emit("executable?");
    });
    
    q.addListener("RowDescription", function (args) {
        q.row_description = args;
        if (exports.DEBUG > 0) {
            sys.debug("Caught RowDescription in Prepared object.");
        }
        q.emit("executable?");
    });
    
    var execute = [];
    
    q.addListener("executable?", function () {
        
        if (exports.DEBUG > 0) {
            sys.debug("hit executable?");
            sys.debug("parseComplete: "+parseComplete);
            sys.debug("readyToExec: " + readyToExec);
            sys.debug((q.row_description != null && q.row_description.length > 0) || q.noData);
        }
        
        if (parseComplete && readyToExec && ((q.row_description != null && q.row_description.length > 0) || q.noData)) {
            conn.release(q); // Yield myself.
            if (exports.DEBUG > 0) {
                sys.debug("Yielding to the next message set.");
            }
        }
        else if (parseComplete && ((q.row_description != null && q.row_description.length > 0) || q.noData)) {
            // The server is prepped. We can now safely run the callback
            // and trap the execute statements, prior to adding them to the
            // main query queue.
            sys.debug("calling callback");
            callback(q);
            q.emit("executable?");
        }
    });
    
    q.addListener("ParameterDescription", function (desc) {
        q.param_description = desc;
        q.emit("executable?");
    });
    
    q.addListener("NoData", function () {
        q.noData = true;
    })
    
    /* 
    Executing the function tests whether or not 
    we've been passed an argument list.
    If we have been, then we need to issue a BIND on the wire.
    If we haven't been, we can move straight to EXECUTE.
    */
    q.execute = function () {
        // If the first argument is an array, then we use that as our bind
        // parameters. Otherwise, arguments[0] should be a function.
        readyToExec = true;
        var eP;
        if (arguments[0] instanceof Array) {
            if (arguments[0].length >= 1) {
                var callback = null;
                // If the functions' a function, yay!
                if (typeof(arguments[1]) == 'function') {
                    callback = arguments[1];
                }
                eP = new execPrepared(portal, prepared_name, q.param_description, arguments[0], q.row_description, conn, arguments[1]);
            }
        }
        else if (typeof(arguments[0]) == 'function' ) {
            eP = new execPrepared(portal, prepared_name, q.param_description, [], q.row_description, conn, arguments[0]);
            // Announcing that my slot is released in favour of this new query.
            // The connection doesn't advance the buffer, but *does* replace 
            // the current query with this one.
        }
        else {
            q.emit("error", "First argument must be array or function!");
        }
        if(exports.DEBUG > 0) {
            sys.debug("Yielding");
        }
        conn.yield_to(q, eP); 
    }
    
    q.next = function() {
        if (arr[pos] !== null) {
            pos = pos + 1;
            return arr[pos-1];
        }
        return null;
    }
}
Prepared.prototype = new process.EventEmitter;

function execPrepared (portal, prepared, params, args, row_desc, conn,  callback) {
    var q = this;
    q.row_description = row_desc;
    var results = [];
    var arr = [
        {
            type: "Execute",
            args: [portal, 0], // No limit. Get all the rows.
        },
        {
            type: "Flush",
            args: [portal, 0]
        }
    ];
    // If we have args, unshift the Bind.
    if (args instanceof Array && args.length >= 1) {
        arr.unshift({
            type: "Bind",
            args:[portal, prepared, params, args],
            callback: callback
        });
    }
    
    q.addListener("BindComplete", function (args) {
        // We can mostly just ignore this, right? It's a notification of
        // okay-ness.
        conn.next();
    });
    
    // Named this instead of DataRow to prevent the main loop from using this,
    // instead of the main connection datarow parser.
    
    q.addListener("newRow", function (row) {
        results.push(row);
    });
    
    q.addListener("CommandComplete", function (data) {
        // Whatever we just did is ended.
        // If it was a SELECT, args will be an array of rows, 
        // If it was an INSERT, etc, it'll be the type, and the number of 
        // affected rows.
        if (exports.DEBUG > 0) {
            sys.debug("Results length " + results.length);
        }
        if (results.length >= 1) {
            if (exports.DEBUG > 0) {
                sys.debug("Calling with results");
            }
            callback.call(q, results);
        }
        else {
            this.type = data.type;
            callback.call(q);
        }
        conn.release(q);
    });
    var pos = 0;
    q.next = function() {
        if (arr[pos] !== null) {
            pos = pos + 1;
            return arr[pos-1];
        }
        return null;
    }
}

execPrepared.prototype = new process.EventEmitter;


/* Initializes a connection to the database.
DB connections are of the form:

pgsql://user:password@hostname:port/databasename

*/

function Connection(args) {
    if (typeof args === 'string') {
        args = url.parse(args);
        args.database = args.pathname.substr(1);
        args.auth = args.auth.split(":");
        args.username = args.auth[0];
        args.password = args.auth[1];
    }
    var started, conn, connection, events, query_queue, current_query, results, readyState, closeState;
    
    // Default to port 5432
    args.port = args.port || 5432;
    
    // Default to host 127.0.0.1
    args.hostname = args.hostname || "127.0.0.1";
    
    connection = net.createConnection(args.port, args.hostname);
    events = new process.EventEmitter();
    query_queue = [];
    readyState = false;
    closeState = false;
    started = false;
    conn = this;
    current_query = null;
  
    // Disable the idle timeout on the connection
    connection.setTimeout(0);

    // Sends a message to the postgres server
    function sendMessage(type, args) {
        if (exports.DEBUG > 0 ) {
            sys.debug("Got type of "+type)
        }
        var buffer = (formatter[type].apply(this, args)).frame();
        if (exports.DEBUG > 0) {
            sys.debug("Sending " + type + ": " + JSON.stringify(args));
            if (exports.DEBUG > 2) {
                sys.debug("->" + buffer.inspect().replace('<', '['));
            }
        }
        connection.write(buffer);
        if (current_query) {
            conn.next(current_query); // We don't always expect to get a response message.
                         // And if we do, the message object can sort it out.
        }
    }
    
    var queue = [];
    function checkInput() {
        if (queue.length === 0) { return; }
        var first = queue[0];
        var code = String.fromCharCode(first[0]);
        var length = first.int32Read(1) - 4;
        
        // Make sure we have a whole message, TCP comes in chunks
        if (first.length < length + 5) {
            if (queue.length > 1) {
                // Merge the first two buffers
                queue.shift();
                var b = new Buffer(first.length + queue[0].length);
                first.copy(b);
                queue[0].copy(b, first.length);
                queue[0] = b;
                return checkInput();
            } else {
                return;
            }
        }
        // What does this do?
        var message = first.slice(5, 5 + length);
        if (first.length === 5 + length) {
            queue.shift();
        } else {
            queue[0] = first.slice(length + 5, first.length);
        }
        
        if (exports.DEBUG > 1) {
            sys.debug("stream: " + code + " " + message.inspect());
        }
        // This shouldn't block. 
        // TODO: Rewrite into a callback.
        command = parse_response(code, message);
        if (command.type) {
            if (exports.DEBUG > 0) {
                sys.debug("Received " + command.type + ": " + JSON.stringify(command.args));
            }
            command.args.unshift(command.type);
            // Uses a selective emitter.
            // First, tests whether or not the executing query listens to the event.
            // This permits a given query to take over selected aspects of the 
            // If not, fires on the primary (connection) event loop.
            if (exports.DEBUG > 0) {
                sys.debug("current_query is null: "+ current_query !== null);
                if (current_query !== null) {
                    sys.debug("current_query listeners: " + current_query.listeners(command.type).length);
                }
            }
            if (current_query !== null && current_query.listeners(command.type).length >= 1) {
                if (exports.DEBUG > 0) {
                    sys.debug("Sending  "+command.type+" to current_query");
                }
                current_query.emit.apply(current_query, command.args);
            }
            else {
                if (exports.DEBUG > 0) {
                    sys.debug("Sending  "+command.type+" to local handler");
                }
                events.emit.apply(events, command.args);
            }
        }
        checkInput();
    }
    
    // Set up tcp client
    connection.addListener("connect", function () {
        sendMessage('StartupMessage', [{user: args.username, database: args.database}]);
    });
    connection.addListener("data", function (data) {
        if (exports.DEBUG > 2) {
            sys.debug("<-" + data.inspect());
        }
        queue.push(data);
        checkInput();
    });
    connection.addListener("end", function (data) {
        connection.end();
    });
    connection.addListener("disconnect", function (had_error) {
        if (had_error) {
            sys.debug("CONNECTION DIED WITH ERROR");
        }
    });
    
    // Set up callbacks to automatically do the login and other logic
    events.addListener('AuthenticationMD5Password', function (salt) {
        var result = "md5" + md5(md5(args.password + args.username) + salt.toString("binary"));
        sendMessage('PasswordMessage', [result]);
    });
    events.addListener('AuthenticationCleartextPassword', function () {
        sendMessage('PasswordMessage', [args.password]);
    });
    events.addListener('ErrorResponse', function (e) {
        conn.emit('error', e.S + ": " + e.M);
        if (e.S === 'FATAL') {
            connection.end();
        }
    });
    
    events.addListener('ReadyForQuery', function () {
        if (exports.DEBUG > 0) {
            sys.debug("In RFQ");
        }
        if (!started) {
            started = true;
            conn.emit('connection');
        }
        
        if (closeState) {
            connection.end();
        } else {
            readyState = true;
        }
        if (exports.DEBUG > 0) {
            sys.debug(readyState);
            sys.debug("Queue length: "+query_queue.length);
        }
        
        if (query_queue.length > 0 && readyState !== false) {
            
            var query = query_queue.shift();
            current_query = query;
            
            /*
            query_callback = query.callback;
            row_callback = query.row_callback;
            
            // Implicit assumption we're only putting queries on the wire.
            sendMessage('Query', [query.sql]);
            */
            
            readyState = false;
            events.emit("nextMessage");
            
        }
    });
    // This should always be caught by the current query.
    events.addListener("RowDescription", function (data) {
        row_description = data;
        results = [];
    });
    
    // This is no longer correct. Sigh.
    
    events.addListener("DataRow", function (data) {
        var row, i, l, description, value;
        row = {};
        l = data.length;
        for (i = 0; i < l; i += 1) {
            description = current_query.row_description[i];
            value = data[i];
            if (value !== null) {
                // TODO: investigate to see if these numbers are stable across databases or
                // if we need to dynamically pull them from the pg_types table
                switch (description.type_id) {
                    case 16: // bool
                        value = value === 't';
                        break;
                    case 20: // int8
                    case 21: // int2
                    case 23: // int4
                        value = parseInt(value, 10);
                        break;
                }
            }
            row[description.field] = value;
        }
        if (exports.DEBUG > 0) {
            sys.debug(current_query.listeners("newRow").length);
            sys.debug(current_query);
        }
        if (current_query.listeners("newRow").length > 0) {
            current_query.emit("newRow", row);
        }
        else {
            results.push(row)
        }
    });
    
    
    events.addListener('CommandComplete', function (data) {
        if (results.length >= 1) {
            // To allow for insert..returning
            current_query.emit("Complete", results, data);
            results = []; // blank the current result buffer.
        }
        else {
            // Send the typing information.
            current_query.emit("Complete", data);
        }
        // query_callback.call(this, results);
    });
    
    conn.query = function query(query) {
        var parameters, callback;
        
        // Grab the variable length parameters and the row_callback is there is one.
        parameters = Array.prototype.slice.call(arguments, 1);
        
        if (typeof parameters[parameters.length - 1] === 'function') {
            callback = parameters.pop();
        }
        var q;
        if (parameters.length == 1 && parameters[0] instanceof Array) {
            // We have a parameterized query
            q = new Prepared(query, function (sth) {
                sth.execute(parameters[0], callback);
            });
        }
        else {
            q = new Query(query, callback);
            
        }
        query_queue.push(q);
        events.emit("queryAdded");
    };
    
    conn.prepare = function prepare(query, callback) {
        // Sets up a prepared query, and drops it onto the queue.
        query_queue.push(
            new Prepared(query, conn, callback)
        );
        events.emit("queryAdded");
        // conn.emit.call(conn, "queryAdded");
    }
    
    this.end = function () {
        closeState = true;
        
        // Close the connection right away if there are no pending queries
        if (readyState) {
            connection.end();
        }
    };
    
    events.addListener("queryAdded", function () {
        if (readyState) {
            conn.emit("ReadyForQuery");
        }
    });
    
    /* Allows a currently-executing query to selectively modify the current
       query queue, IF it is currently executing.
       
       Otherwise, it splices the query object in after its position in the queue.
    */
    conn.yield_to = function (first, query) {
        if (exports.DEBUG > 0) {
            sys.debug("got yield_to");
        }
        if (first === current_query) {
            query_queue.unshift(query);
            events.emit("queryAdded"); // Don't immediately switch to the next message.
        }
        else if (first in query_queue) {
            // Splice it in after the query
            query_queue.splice( query_queue.indexOf(first), 0, query );
            events.emit("queryAdded");
        }
    }
    
    conn.release = function (query) {
        if (exports.DEBUG > 0) {
            sys.debug("got release");
        }
        if (query === current_query) {
            readyState = true;
            events.emit("ReadyForQuery"); // Cycle along.
        }
    }
    
    // Pumps the current_query queue via .next()
    // and runs whatever we get back.
    events.addListener("nextMessage", function () {
        
        if (events.DEBUG > 0) {
            sys.debug("got nextMessage");
        }
        
        var msg;
        if (current_query !== null) {
            
            if (exports.DEBUG > 0) {
                sys.debug("current query is not Null.");
            }
            
            msg = current_query.next();
            
            if (exports.DEBUG > 0) {
                sys.debug("Message is: "+msg);
            }
            
            if (msg !== undefined && msg.type && msg.args) {
                // We have what we need to perform this query.
                sendMessage.apply(conn, [msg.type, msg.args]);
            }
        } 
    });
    
    conn.next = function (query) {
        if (query === current_query) {
            events.emit("nextMessage");
        }
        // If it's not, why are you doing this?
    }
    
    /*
    Keeps watch for the addition of listeners on our connection.
    This allows for monitoring the driver for notification requests, which, 
    in turn, allows us to catch that the user wants this particular 
    notification from the DB watched for.
    
    Ergo, we set up a DB listener with the same name, and fire our emitter
    when it's triggered.
    
    Easy.
    */
    conn.addListener('newListener', function (e, listener) {
        if (e === 'String') {
            // It's a string.
            if (!(e in ['newListener']))
            conn.notify(e, listener);
        }
        
    });
}
Connection.prototype = new process.EventEmitter();


/*
Connection.prototype.get_store = function (name, columns) {
  return new sqllib.Store(this, name, columns, {
    do_insert: function (data, keys, values, callback) {
      this.conn.query("INSERT INTO " +
        this.name + "(" + keys.join(", ") + ")" +
        " VALUES (" + values.join(", ") + ")" +
        " RETURNING _id",
        function (result) {
          data._id = parseInt(result[0]._id, 10);
          callback(data._id);
        }
      );
    },
    index_col: '_id',
    types: ["_id SERIAL"]
  });
};
*/
exports.connect = Connection;

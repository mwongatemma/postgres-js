/*jslint bitwise: true, eqeqeq: true, immed: true, newcap: true, nomen: true, onevar: true, plusplus: true, regexp: true, undef: true, white: true, indent: 2 */
/*globals include md5 node exports */

/* Expected flow is:
   Query
    * RowDescription
    * DataRow
    * CommandComplete
    * ReadyForQuery
   Parse
    * Parse
    * ParseCompleted
   Bind
    * Bind
    * BindCompleted
   Execute
    * Execute
*/

process.mixin(require('./lib/md5'));

var bits = require('./lib/bits');
var oid = require("./lib/type-oids");
var parsers = require("./lib/parsers");
var tcp = require("tcp");
var sys = require("sys");

exports.DEBUG = 1;

var postgres_parameters = {};

// http://www.postgresql.org/docs/8.3/static/protocol-message-formats.html
var formatter = {
  
  Bind: function (name, statement, args) {
      var b = (new bits.Encoder('B'))
        .push_cstring(name)     // The name of the bound portal
        .push_cstring(statement) // The name of the prepared statement
        .push_int16(args.length); // Add the number of format codes.
        //.push_int16(0) // Marks them all as text
      for (var i = 0; i < args.length; i++) {
          b.push_int16(0);        // Mark them all text.
      }
      b.push_int16(args.length); // Add the number of parameters.
      
      for (var i = 0; i < args.length; i++) {
          // Add the size of the parameter.
          b.push_int32( process._byteLength(args[i]) ); // Add the length of the argument
          b.push_raw_string( args[i] ); // Add the argument itself.
          
      };
      b.push_int16(1);
      b.push_int16(0);
      //b.push_int16(0); // Mark that we don't know what the response is going to be.
      //b.push_int16(0); 
      //b.push_int16(0); // All of them should be text.
      
      return b;
  },
  
  CopyData: function () {
    // TODO: implement
  },
  CopyDone: function () {
    // TODO: implement
  },
  Describe: function (name, type) {
    return (new bits.Encoder('D'))
      .push_raw_string(type)
      .push_cstring(name);
  },
  Execute: function (name, max_rows) {
    return (new bits.Encoder('E'))
      .push_cstring(name)
      .push_int32(max_rows);
  },
  Flush: function () {
    return new bits.Encoder('H');
  },
  FunctionCall: function () {
    // TODO: implement
  },
  Parse: function (name, query, args) {
      if (exports.DEBUG > 0) {
          sys.debug("Name is " + name);
          sys.debug("Query is " + query);
          sys.debug("Args are " + args);
      }
    var builder = (new bits.Encoder('P'))
      .push_cstring(name)
      .push_cstring(query);
      // sys.p(args);
    if (args.length > 0) {
        builder.push_int16(args.length);
        for (var i = 0; i <= args.length; i++) {
            builder.push_int32(0);
        }
    }
    else {
        builder.push_int16(0);
        // builder.push_int32(0);
        // No types.
    }
    return builder;
  },
  PasswordMessage: function (password) {
    return (new bits.Encoder('p'))
      .push_cstring(password);
  },
  Query: function (query) {
    return (new bits.Encoder('Q'))
      .push_cstring(query);
  },
  SSLRequest: function () {
    return (new bits.Encoder())
      .push_int32(0x4D2162F);
  },
  StartupMessage: function (options) {
    // Protocol version number 3
    return (new bits.Encoder())
      .push_int32(0x30000)
      .push_hash(options);
  },
  Sync: function () {
    return new bits.Encoder('S');
  },
  Terminate: function () {
    return new bits.Encoder('X');
  }
};

// Parse response streams from the server
function parse_response(code, stream) {
  var input, type, args, num_fields, data, size, i;
  input = new bits.Decoder(stream);
  args = [];
  switch (code) {
  case 'R':
    switch (stream.shift_int32()) {
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
      args = [stream.shift_raw_string(2)];
      break;
    case 5:
      type = "AuthenticationMD5Password";
      args = [stream.shift_raw_string(4)];
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
    }
    break;
  case 'E':
    type = "ErrorResponse";
    args = [{}];
    stream.shift_multi_cstring().forEach(function (field) {
      args[0][field[0]] = field.substr(1);
    });
    break;
  case 'S':
    type = "ParameterStatus";
    args = [stream.shift_cstring(), stream.shift_cstring()];
    break;
  case 't':
    type = "ParameterDescription";
    var len = stream.shift_int16();
    var data = [];
    for (var i = 0; i < len; i++) {
        data.push( stream.shift_int32 );
    }
    args = data;
    break;
  case 'K':
    type = "BackendKeyData";
    args = [stream.shift_int32(), stream.shift_int32()];
    break;
  case 'Z':
    type = "ReadyForQuery";
    args = [stream.shift_raw_string(1)];
    break;
  case 'T':
    type = "RowDescription";
    num_fields = stream.shift_int16();
    data = [];
    for (i = 0; i < num_fields; i += 1) {
      data.push({
        field: stream.shift_cstring(),
        table_id: stream.shift_int32(),
        column_id: stream.shift_int16(),
        type_id: stream.shift_int32(),
        type_size: stream.shift_int16(),
        type_modifier: stream.shift_int32(),
        format_code: stream.shift_int16()
      });
    }
    args = [data];
    break;
  case 'D':
    type = "DataRow";
    data = [];
    num_fields = stream.shift_int16();
    for (i = 0; i < num_fields; i += 1) {
      size = stream.shift_int32();
      if (size === -1) {
        data.push(null);
      } else {
        data.push(stream.shift_raw_string(size));
      }
    }
    args = [data];
    break;
  case 'C':
    type = "CommandComplete";
    args = [stream.shift_cstring()];
    break;

  case '1': // Parse Complete.
    if (exports.DEBUG > 0) {
        sys.debug("Got a ParseComplete message.");
    }
    type = "ParseComplete";
    args = [stream.shift_int32];
    break;
  case '2':
    type = "BindComplete";
    break;
  }
  if (!type) {
    sys.debug("Unknown response " + code);  
  }
  return {type: type, args: args};
}


exports.connect = function (database, username, password, port, host) {
  var connection, events, query_queue, row_description, query_callback, results, readyState, closeState;
  
  // Default to port 5432
  if (port === undefined) {
    port = 5432;
  }
  
  t_host = host;
  if (t_host === undefined) {
      t_host = "localhost";
  }

  connection = tcp.createConnection(port, host=t_host);
  events = new process.EventEmitter();
  query_queue = [];
  readyState = false;
  closeState = false;
  needsFlush = false;
  msg_queue = [];
  
  var cQuery; // This is the currently executing query.
  
  canQuery = false;
  
  // Sends a message to the postgres server
  function sendMessage(type, args) {
      
      if (exports.DEBUG > 0) {
          sys.debug("Type is " + type);
          sys.debug("Args are " + args);
      }
      
      var stream = (formatter[type].apply(this, args)).toString();
      if (exports.DEBUG > 0) {
        sys.debug("Sending " + type + ": " + JSON.stringify(args));
        if (exports.DEBUG >= 2) {
          sys.debug("->" + JSON.stringify(stream));
        }
      }
      connection.send(stream, "binary");
  }
  
  // Set up tcp client
  connection.setEncoding("binary");
  connection.addListener("connect", function () {
    sendMessage('StartupMessage', [{user: username, database: database}]);
  });
  
  //
  connection.addListener("receive", function (data) {
    var input, code, len, stream, command;
    if (exports.DEBUG > 1){
        sys.debug("Got a response. Attempting to decode.");
    }
    input = new bits.Decoder(data);
    if (exports.DEBUG > 2) {
      sys.debug("<-" + JSON.stringify(data));
    }
  
    while (input.data.length > 0) {
      code = input.shift_code();
      len = input.shift_int32();
      stream = new bits.Decoder(input.shift_raw_string(len - 4));
      if (exports.DEBUG > 1) {
        sys.debug("stream: " + code + " " + JSON.stringify(stream));
      }
      command = parse_response(code, stream);
      if (command.type) {
        if (exports.DEBUG > 1) {
          sys.debug("Received " + command.type + ": " + JSON.stringify(command.args));
        }
        command.args.unshift(command.type);
        if (cQuery != null && cQuery.events != undefined) {
            if (exports.DEBUG > 0) {
                sys.debug ("Current query is not null and current query is " + cQuery.type);
            }
            if (cQuery.events.listeners(command.type).length >= 1) {
                cQuery.events.emit.apply(cQuery.events, command.args);
            }
            else {
                events.emit.apply(events, command.args);
            }
        }
        else {
            events.emit.apply(events, command.args);
        }
      }
    }
  });
  //
  connection.addListener("eof", function (data) {
    connection.close();
  });
  //
  connection.addListener("disconnect", function (had_error) {
    if (had_error) {
      sys.debug("CONNECTION DIED WITH ERROR");
    }
  });
  
  // Set up callbacks to automatically do the login
  events.addListener('AuthenticationMD5Password', function (salt) {
    var result = "md5" + md5(md5(password + username) + salt);
    sendMessage('PasswordMessage', [result]);
  });
  //
  events.addListener('AuthenticationCleartextPassword', function () {
    sendMessage('PasswordMessage', [password]);
  });
  //
  events.addListener('ErrorResponse', function (e) {
    if (e.S === 'FATAL') {
      sys.debug(e.S + ": " + e.M);
      connection.close(); // Well, that's bad.
    }
    if (e.S === "ERROR") {
        // var err = new Error();
        // err.name = "Error";
        // err.message = e.M;
        // throw err;
        sys.p(e);
        msg = new String(e.M);
        throw new Error("DB Error: " + msg);
    }
  });
  //
  
  events.addListener('ParameterStatus', function(key, value) {
      postgres_parameters[key] = value;
  });
  
  function queue (msg) {
      msg_queue.push(msg);
  }
  
  function flush (promise, eventHandler) {
      // We now flush all entries in the queue. 
      // We iterate the query_queue, send each message, and finally use the 
      // object provided us as the Event responder for this query set. 
      
      var q = {type:"Flush", events:eventHandler, promise: promise};
      msg_queue.push(q);
      sys.debug(canQuery);
      
      if (canQuery) {
          events.emit("FlushBuffer");
      }
  }
  
  function send (msg) {
      
      if (canQuery && !closeState) {
          // immediately send the message
          canQuery = false;
          cQuery = msg;
          sendMessage(msg.type, cQuery.args);
      }
      else if (closeState) {
          // Raise an error
          throw new Error("Cannot execute queries on closed handle.");
      }
      else {
          // Push it onto the stack, and return.
          msg_queue.push(msg);
      }
  }
  
  // The main query buffer; this handles *all* query traffic.
  
  events.addListener("FlushBuffer", function () {
      
      if (msg_queue.length > 0) {
          canQuery = false;
          var i;
          var len = msg_queue.length;
          for (i = 0; i < len; i++) {
              var Query = msg_queue.shift();
              if (exports.DEBUG > 0) {
                sys.debug("RFQ: "+Query.type);
              }
              if (Query.type == "Flush") {
                  cQuery = Query;
                  sendMessage(Query.type, Query.args);
                  break; // Exit this loop.
              }
              else {
                  // Just send the message.
                  sendMessage(Query.type, Query.args);
              }
          }
        // var Query = msg_queue.shift(); // Grab the first.

        // query_callback = query.callback || function () {};
      } else {
        // if (closeState) {
        //     // This is not how we should be shutting down.
        // 
        //     connection.close();
        // } else {
          canQuery = true;
          cQuery = null; // Done and Handled.
      }
      
  });
  
  
  events.addListener('ReadyForQuery', function () {
      
      if (msg_queue.length > 0) {
          events.emit("FlushBuffer");
      } else {
        if (closeState) {
            // This is not how we should be shutting down.
            sys.debug("Got shutdown.");
            msg_queue.push({type:"Terminate", args:[]});
            connection.close(); // Shut it all down.
        }
      }
      // // Do we have anything on the buffer?
      // if (msg_queue.length > 0) {
      //     events.emit("FlushBuffer");
      // }
      // else if (closeState) {
      //     msg_queue.push({type:"Terminate", });
      // }

  });
  
  events.addListener("RowDescription", function (data) {
    cQuery.row_description = data;
    cQuery.results = [];
  });
  
  events.addListener("DataRow", function (data) {
      dataParser(data, cQuery); // use the global query context.
  });
  
  function dataParser (data, mQuery) {
    var row, i, l, description, value;
    row = {};
    l = data.length;
    for (i = 0; i < l; i += 1) {
      description = mQuery.row_description[i];
      value = data[i];
      if (value !== null) {
        // TODO: investigate to see if these numbers are stable across databases or
        // if we need to dynamically pull them from the pg_types table
        switch (description.type_id) {
        case oid.BOOL:
          value = value === 't';
          break;
        case oid.INT8:
        case oid.INT2:
        case oid.INT4:
          value = parseInt(value, 10);
          break;
        case oid.DATE:
        case oid.TIME:
        case oid.TIMESTAMP:
        case oid.TIMESTAMPTZ:
          value = parsers.parseDateFromPostgres(
                            value,
                            postgres_parameters['DateStyle'],
                            description.type_id
                          );
          break;
        }
      }
      row[description.field] = value;
    }
    mQuery.results.push(row);
  };
  events.addListener('CommandComplete', function (data) {
      // cQuery.promise.emitSuccess(data);
      cQuery.promise.emitSuccess( cQuery.results );
      //query_callback.call(this, results);
  });
  
  events.addListener("Notice", function (data) {
      // This is a string message from PG - not an error.
      sys.puts(d.S + " :: " + d.M);
  });
  
  
  this.query = function (sql, args) {
      var p = new process.Promise();
      if (sql.match(/\?/)) {
          // We will do an anonymous prepared statement.
          ;
      }
      else {
          // We can just emit a simple query.
          
          queue({type:"Query", args:[sql], promise: p});
          return p;
      }
  };
  
  this.prepare = function (query) {
      
      var p = new process.Promise();
      
      var treated = query;
      var i = 0;
      var arglist = new Array();
      // Replace all ?'s with bind parameters.
      if (query.match(/\?/)) {
          treated = treated.replace(/\?/g, function (str, p1, offset, s) {
              i = i + 1;
              arglist.push(0); // a null string, representing that it is, in fact, an item.
              return "$"+i;
          });
      }
      var name = md5(md5(query));
      var offset = Math.floor(Math.random() * 10);
      name = "postgres_js_prepared_" + name.replace(/\d/g, "").slice(offset,4+offset);
      
      // Assumes, for the moment, that all the bind variables are going to be
      // text, as we otherwise don't know what they are.
      
      var e = new process.EventEmitter();
      var Stmt = new Statement(name, i, p);
      e.addListener("ParseComplete", function (data) {
          // Our next message is (probably) going to be a ReadyForQuery.
          canQuery = true; // Say that we now allow for more queries on the wire.
          if (exports.DEBUG > 0) {
              sys.debug("Prepare:: ParseComplete message received.");
          }
          p.emitSuccess();
      });
      
      queue( {type:"Parse", args:[name, treated, []] } );
      
      var rowDesc = [];
      flush(p, e); // Issues the implied Flush command.
      
      //return p;
      return Stmt;
  };
  
  function Statement (name, len, prepared) {
      // Execute sets up a bind, and then executes the statement.
      //queue( {type:"Describe", args:[name] });
      
      // Until it's prepared, we won't ever Flush. This all becomes
      // asynchronous
      
      var format;
      var row_description = [];
      
      var isPrepared = false;
      var iBuffer = [];
      
      var isDescribed = false;
      
      prepared.addCallback(function () {
          if (exports.DEBUG > 0) {
              sys.debug("Statement:: Prepare completed.");
          }
          isPrepared = true;
          // If there's any buffered executes, perform them now.
          // 
          if (iBuffer.length > 0) {
              if (exports.DEBUG > 0) {
                  sys.debug("Found internal buffer.");
              }
              for (var i = 0; i < iBuffer.length; i++) {
                  var o = iBuffer[i];
                  if (o.type == "Flush") {
                      if (exports.DEBUG > 0) {
                          sys.debug("Flushing.");
                      }
                      flush(o.promise, o.events);
                  }
                  else {
                      if (exports.DEBUG > 0) {
                          sys.debug("Queuing "+ o.type);
                      }
                      queue(o);
                  }
              }
              iBuffer = []; // Zero it.
          }
      });
      
      this.execute = function (args) {
          
          if (args.length > len) {
              throw new Error("Cannot execute: Too many arguments");
          }
          else if (args.length < len) {
              
              // We need to pad out the length with nulls
              for (var i = args.length; i<= len; i++) {
                  args.push(null);
              }
          }
          var e = new process.EventEmitter();
          var promise = new process.Promise();
          
          // var our = this;
          // our.results = [];
          var our = new Object();
          var obj = this;
          our.results = [];
          our.row_description = null;
          e.addListener("BindComplete", function (data) {
              // This is good, but we don't need to do anything as a result.
              if (exports.DEBUG > 0) {
                  sys.debug("got Bind Complete");
              }
          });
          
          e.addListener("ParameterDescription", function (data) {
              // Defines what our system actually needs to send. For the 
              // moment, we don't need to worry about this.
              if (exports.DEBUG > 0) {
                  sys.debug("got Parameter Description");
              }
          });
          
          e.addListener("RowDescription", function (data) {
              if (exports.DEBUG > 0) {
                  sys.debug("got Row Description");
              }
              obj.row_description = data;
              our.results = [];
              isDescribed = true;
          });
          
          e.addListener("DataRow", function (data) {
              if (exports.DEBUG > 0) {
                  sys.debug("got a Data Row");
              }
              if (our.row_description == null) {
                  our.row_description = obj.row_description;
              }
              dataParser(data, our);
          });
          
          e.addListener("CommandComplete", function (data) {
              if (exports.DEBUG > 0) {
                  sys.debug("got CommandComplete");
              }
              promise.emitSuccess(our.results);
              events.emit("ReadyForQuery");
          });
          
          
          if (isPrepared == true) {
              
              if (!(isDescribed)) {
                  queue( {type:"Describe", args:[name, "S"] } );
                  isDescribed = true;
              }
              // We use the main buffer for queries.
              queue( {type:"Bind", args:["", name, args] } );
              queue( {type:"Execute", args:["", 0] } );
              flush(promise, e); // Issues the implied Flush command.
          }
          else if (isPrepared == false) {
              // we buffer internally until we get the main buffering response.
              
              if (!(isDescribed)) {
                  iBuffer.push( {type:"Describe", args:[name, "S"] } );
                  isDescribed = true;
              }
              
              iBuffer.push( {type:"Bind", args:["", name, args] } );
              iBuffer.push( {type:"Execute", args:["", 0] } );
              iBuffer.push( {type:"Flush", events: e, promise: p } ); 
          }
          return promise; // Return our Promise.
      };
  }
  
  this.close = function () {
      // This needs to be updated to handle a DB-side close
      closeState = true;
  };
  
};
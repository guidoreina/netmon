// Function: validTimestamp
// Description: receives as input a timestamp with the format
// 'YYYY/MM/DD hh:mm:ss.uuuuuu' and returns whether the timestamp is valid.
// Parameter: timestamp with the format 'YYYY/MM/DD hh:mm:ss.uuuuuu'.
// Returns: true: if the timestamp is valid; false: otherwise.
function validTimestamp(timestamp)
{
  var res = /(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2}).(\d{6})/.exec(timestamp);

  return ((res) && (res.length === 8));
}


// Function: parseTimestamp
// Description: receives as input a timestamp with the format
// 'YYYY/MM/DD hh:mm:ss.uuuuuu' and returns a Date object.
// Parameter: timestamp with the format 'YYYY/MM/DD hh:mm:ss.uuuuuu'.
// Returns: Date object.
// Might throw: yes.
function parseTimestamp(timestamp)
{
  var res = /(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2}).(\d{6})/.exec(timestamp);

  let year = res[1];
  let mon  = res[2];
  let mday = res[3];
  let hour = res[4];
  let min  = res[5];
  let sec  = res[6];
  let usec = res[7];

  return new Date(year, mon - 1, mday, hour, min, sec, usec / 1000);
}


// Base event.
class BaseEvent {
  // Constructor.
  constructor(ev) {
    this.number    = ev['event-number'];
    this.timestamp = parseTimestamp(ev['date']);
    this.saddr     = ev['source-ip'];
    this.daddr     = ev['destination-ip'];

    // If there is source hostname...
    if (ev.hasOwnProperty('source-hostname')) {
      this.srchost = ev['source-hostname'];
    } else {
      this.srchost = null;
    }

    // If there is destination hostname...
    if (ev.hasOwnProperty('destination-hostname')) {
      this.dsthost = ev['destination-hostname'];
    } else {
      this.dsthost = null;
    }
  }

  // Valid event?
  static valid(ev) {
    return ((ev.hasOwnProperty('event-number')) &&
            (ev.hasOwnProperty('date')) &&
            (ev.hasOwnProperty('event-type')) &&
            (ev.hasOwnProperty('source-ip')) &&
            (ev.hasOwnProperty('destination-ip')) &&
            (validTimestamp(ev['date'])));
  }
}


// 'ICMP' event.
class IcmpEvent extends BaseEvent {
  // Constructor.
  constructor(ev) {
    super(ev);

    this.icmp_type   = ev['icmp-type'];
    this.icmp_code   = ev['icmp-code'];
    this.transferred = ev['transferred'];
  }

  // Valid 'ICMP' event?
  static valid(ev) {
    return ((BaseEvent.valid(ev)) &&
            (ev.hasOwnProperty('icmp-type')) &&
            (ev.hasOwnProperty('icmp-code')) &&
            (ev.hasOwnProperty('transferred')));
  }
}


// 'UDP' event.
class UdpEvent extends BaseEvent {
  // Constructor.
  constructor(ev) {
    super(ev);

    this.sport       = ev['source-port'];
    this.dport       = ev['destination-port'];
    this.transferred = ev['transferred'];
  }

  // Valid 'UDP' event?
  static valid(ev) {
    return ((BaseEvent.valid(ev)) &&
            (ev.hasOwnProperty('source-port')) &&
            (ev.hasOwnProperty('destination-port')) &&
            (ev.hasOwnProperty('transferred')));
  }
}


// 'DNS' event.
class DnsEvent extends BaseEvent {
  // Constructor.
  constructor(ev) {
    super(ev);

    this.sport       = ev['source-port'];
    this.dport       = ev['destination-port'];
    this.transferred = ev['transferred'];
    this.qtype       = ev['query-type'];
    this.domain      = ev['domain'];

    // DNS response?
    if (ev.hasOwnProperty('responses')) {
      this.responses = ev['responses'];
    } else {
      this.responses = null;
    }
  }

  // Valid 'DNS' event?
  static valid(ev) {
    return ((BaseEvent.valid(ev)) &&
            (ev.hasOwnProperty('source-port')) &&
            (ev.hasOwnProperty('destination-port')) &&
            (ev.hasOwnProperty('transferred')) &&
            (ev.hasOwnProperty('query-type')) &&
            (ev.hasOwnProperty('domain')));
  }
}


// 'Begin TCP connection' event.
class TcpBeginEvent extends BaseEvent {
  // Constructor.
  constructor(ev) {
    super(ev);

    this.sport = ev['source-port'];
    this.dport = ev['destination-port'];
  }

  // Valid 'Begin TCP connection' event?
  static valid(ev) {
    return ((BaseEvent.valid(ev)) &&
            (ev.hasOwnProperty('source-port')) &&
            (ev.hasOwnProperty('destination-port')));
  }
}


// 'TCP data' event.
class TcpDataEvent extends BaseEvent {
  // Constructor.
  constructor(ev) {
    super(ev);

    this.sport   = ev['source-port'];
    this.dport   = ev['destination-port'];
    this.payload = ev['payload'];
  }

  // Valid 'TCP data' event?
  static valid(ev) {
    return ((BaseEvent.valid(ev)) &&
            (ev.hasOwnProperty('source-port')) &&
            (ev.hasOwnProperty('destination-port')) &&
            (ev.hasOwnProperty('payload')));
  }
}


// 'End TCP connection' event.
class TcpEndEvent extends BaseEvent {
  // Constructor.
  constructor(ev) {
    super(ev);

    this.sport              = ev['source-port'];
    this.dport              = ev['destination-port'];
    this.creation           = ev['creation'];
    this.transferred_client = ev['transferred-client'];
    this.transferred_server = ev['transferred-server'];
  }

  // Valid 'End TCP connection' event?
  static valid(ev) {
    return ((BaseEvent.valid(ev)) &&
            (ev.hasOwnProperty('source-port')) &&
            (ev.hasOwnProperty('destination-port')) &&
            (ev.hasOwnProperty('creation')) &&
            (ev.hasOwnProperty('transferred-client')) &&
            (ev.hasOwnProperty('transferred-server')));
  }
}


// Connection key.
class ConnectionKey {
  // Constructor.
  constructor(saddr, sport, daddr, dport) {
    if (sport < dport) {
      this.addr1 = saddr;
      this.port1 = sport;

      this.addr2 = daddr;
      this.port2 = dport;
    } else if (sport > dport) {
      this.addr1 = daddr;
      this.port1 = dport;

      this.addr2 = saddr;
      this.port2 = sport;
    } else {
      if (saddr <= daddr) {
        this.addr1 = saddr;
        this.port1 = sport;

        this.addr2 = daddr;
        this.port2 = dport;
      } else {
        this.addr1 = daddr;
        this.port1 = dport;

        this.addr2 = saddr;
        this.port2 = sport;
      }
    }
  }

  // Build key.
  get key() {
    return Symbol.for(`ConnectionKey[${this.addr1}:${this.port1}:
                                     ${this.addr2}:${this.port2}]`);
  }
}


// Connection.
class Connection {
  // Constructor.
  constructor(clientIp,
              clientHostname,
              clientPort,
              serverIp,
              serverHostname,
              serverPort,
              begin,
              timestamp,
              clientPayload,
              serverPayload,
              transferredClient,
              transferredServer) {
    this.clientIp          = clientIp;
    this.clientHostname    = clientHostname;
    this.clientPort        = clientPort;

    this.serverIp          = serverIp;
    this.serverHostname    = serverHostname;
    this.serverPort        = serverPort;

    // Timestamp when the connection was created.
    this.begin             = begin;

    // Timestamp when the connection was terminated.
    this.end               = null;

    // Timestamp of the last packet seen.
    this.timeLastPacket    = timestamp;

    this.clientPayload     = clientPayload;
    this.serverPayload     = serverPayload;

    this.transferredClient = transferredClient;
    this.transferredServer = transferredServer;

    // Payload events.
    this.payloadEvents     = [];
  }
}


// Function: createEvent
// Description: receives as input a JSON event and returns one of the following
// objects:
//   IcmpEvent
//   UdpEvent
//   DnsEvent
//   TcpBeginEvent
//   TcpDataEvent
//   TcpEndEvent
// Parameter: JSON event.
// Returns: javascript event: if the event type is valid; null: otherwise.
// Might throw: yes.
function createEvent(ev)
{
  // Get event type.
  let type = ev['event-type'];

  if (type === 'icmp') {
    return new IcmpEvent(ev);
  } else if (type === 'udp') {
    return new UdpEvent(ev);
  } else if ((type === 'dns-query') || (type === 'dns-response')) {
    return new DnsEvent(ev);
  } else if (type === 'begin-tcp-connection') {
    return new TcpBeginEvent(ev);
  } else if (type === 'tcp-data') {
    return new TcpDataEvent(ev);
  } else if (type === 'end-tcp-connection') {
    return new TcpEndEvent(ev);
  } else {
    return null;
  }
}


// Array of events.
let events = [];

const load = () => {
  // Set of DNS clients.
  let dnsClients = new Set();

  // Set of IP addresses.
  let ipAddresses = new Set();

  // Set of hostnames.
  let hostnames = new Set();

  // Set of HTTP servers.
  let httpServers = new Set();

  // Set of HTTPS servers.
  let httpsServers = new Set();

  // For each event...
  for (let i = 0; i < jsonEvents.length; i++) {
    try {
      // Create event.
      let ev = createEvent(jsonEvents[i]);
      if (ev !== null) {
        // Add event to the array of events.
        events.push(ev);

        // DNS query?
        if ((ev instanceof DnsEvent) && (!ev.responses)) {
          // Add source address to the set.
          dnsClients.add(ev.saddr);
        }

        // Add source and destination IP addresses to the set.
        ipAddresses.add(ev.saddr);
        ipAddresses.add(ev.daddr);

        if (ev.srchost) {
          hostnames.add(ev.srchost);
        }

        if (ev.dsthost) {
          hostnames.add(ev.dsthost);
        }

        if (ev instanceof TcpBeginEvent) {
          switch (ev.dport) {
            case 80: // HTTP.
              if (ev.dsthost) {
                httpServers.add(ev.dsthost);
              } else {
                httpServers.add(ev.saddr);
              }

              break;
            case 443: // HTTPS.
              if (ev.dsthost) {
                httpsServers.add(ev.dsthost);
              } else {
                httpsServers.add(ev.saddr);
              }

              break;
          }
        }
      }
    } catch (error) {
      console.error(error);
    }
  }

  // Get DOM element 'dns-clients'.
  let element = document.getElementById('dns-clients');

  // Add DNS clients to the listbox.
  for (let dnsClient of dnsClients) {
    let option = document.createElement('option');

    option.text = dnsClient;
    element.add(option);
  }

  // Get DOM element 'ip-addresses'.
  element = document.getElementById('ip-addresses');

  // Add IP addresses to the listbox.
  for (let ipAddress of ipAddresses) {
    let option = document.createElement('option');

    option.text = ipAddress;
    element.add(option);
  }

  // Get DOM element 'hostnames'.
  element = document.getElementById('hostnames');

  // Add hostnames to the listbox.
  for (let hostname of hostnames) {
    let option = document.createElement('option');

    option.text = hostname;
    element.add(option);
  }

  // Get DOM element 'http-servers'.
  element = document.getElementById('http-servers');

  // Add HTTP servers to the listbox.
  for (let httpServer of httpServers) {
    let option = document.createElement('option');

    option.text = httpServer;
    element.add(option);
  }

  // Get DOM element 'https-servers'.
  element = document.getElementById('https-servers');

  // Add HTTPS servers to the listbox.
  for (let httpsServer of httpsServers) {
    let option = document.createElement('option');

    option.text = httpsServer;
    element.add(option);
  }
}

let connections = null;

function onip(element)
{
  showConnections(document.getElementById(element).value);
}

function showConnections(ipAddress)
{
  // Active connections.
  let activeConnections = new Map();

  // Terminated connections.
  let terminatedConnections = [];

  // For each event...
  for (let i = 0; i < events.length; i++) {
    // 'Begin TCP connection' event?
    if (events[i] instanceof TcpBeginEvent) {
      // If it is the selected IP address...
      if ((ipAddress === events[i].saddr) || (ipAddress === events[i].daddr)) {
        // Create connection key.
        let key = new ConnectionKey(events[i].saddr,
                                    events[i].sport,
                                    events[i].daddr,
                                    events[i].dport).key;

        // Search connection in the list of active connections.
        let conn = activeConnections.get(key);

        // If the connection exists...
        if (conn) {
          // Add connection to the list of terminated connections.
          terminatedConnections.push(conn);

          // Remove connection from the list of active connections.
          activeConnections.delete(key);
        }

        // Create connection.
        conn = new Connection(events[i].saddr,     // Client IP.
                              events[i].srchost,   // Client hostname.
                              events[i].sport,     // Client port.
                              events[i].daddr,     // Server IP.
                              events[i].dsthost,   // Server hostname.
                              events[i].dport,     // Server port.
                              events[i].timestamp, // Connection begin.
                              events[i].timestamp, // Timestamp.
                              0,                   // Payload client.
                              0,                   // Payload server.
                              0,                   // Transferred client.
                              0);                  // Transferred server.

        // Add connection to the list of active connections.
        activeConnections.set(key, conn);
      }
    } else if (events[i] instanceof TcpDataEvent) {
      // 'TCP data' event.

      // If it is the selected IP address...
      if ((ipAddress === events[i].saddr) || (ipAddress === events[i].daddr)) {
        // Create connection key.
        let key = new ConnectionKey(events[i].saddr,
                                    events[i].sport,
                                    events[i].daddr,
                                    events[i].dport).key;

        // Search connection in the list of active connections.
        let conn = activeConnections.get(key);

        // If the connection exists...
        if (conn) {
          // Client to server?
          if ((events[i].saddr === conn.clientIp) &&
              (events[i].sport === conn.clientPort)) {
            // Increment client payload.
            conn.clientPayload += events[i].payload;
          } else {
            // Increment server payload.
            conn.serverPayload += events[i].payload;
          }

          // Update timestamp of the last packet seen.
          conn.timeLastPacket = events[i].timestamp;

          // Add payload event.
          conn.payloadEvents.push(events[i]);
        }
      }
    } else if (events[i] instanceof TcpEndEvent) {
      // 'End TCP connection' event.

      // If it is the selected IP address...
      if ((ipAddress === events[i].saddr) || (ipAddress === events[i].daddr)) {
        // Create connection key.
        let key = new ConnectionKey(events[i].saddr,
                                    events[i].sport,
                                    events[i].daddr,
                                    events[i].dport).key;

        // Search connection in the list of active connections.
        let conn = activeConnections.get(key);

        // If the connection exists...
        if (conn) {
          conn.transferredClient = events[i].transferred_client;
          conn.transferredServer = events[i].transferred_server;

          // Update timestamp of the last packet seen.
          conn.timeLastPacket = events[i].timestamp;

          // Update timestamp of the end connection.
          conn.end = events[i].timestamp;

          // Add connection to the list of terminated connections.
          terminatedConnections.push(conn);

          // Remove connection from the list of active connections.
          activeConnections.delete(key);
        }
      }
    }
  }

  connections = [];

  // Add active connections.
  for (let [k, v] of activeConnections) {
    connections.push(v);
  }

  // Add terminated connections.
  for (let i = 0; i < terminatedConnections.length; i++) {
    connections.push(terminatedConnections[i]);
  }

  // Sort connections.
  connections.sort((ev1, ev2) => ev1.begin.getTime() -
                                 ev2.begin.getTime());

  // Build table with all the connections.
  let table = '<div class="table">';

  // Start of header.
  table += '<div class="heading">';

  table += '<div class="cell">Begin</div>';
  table += '<div class="cell">End</div>';
  table += '<div class="cell">Time last packet</div>';
  table += '<div class="cell">Client IP</div>';
  table += '<div class="cell">Client port</div>';
  table += '<div class="cell">Server IP</div>';
  table += '<div class="cell">Server port</div>';
  table += '<div class="cell">Client payload</div>';
  table += '<div class="cell">Server payload</div>';
  table += '<div class="cell">Transferred client</div>';
  table += '<div class="cell">Transferred server</div>';

  // End of header.
  table += '</div>';

  // Add connections.
  for (let i = 0; i < connections.length; i++) {
    // Start row.
    table += '<div class="row" id="' + getAllConnectionsRowId(i) + '">';

    const divcell = '<div class="cell">';

    // Begin.
    table += (divcell + connections[i].begin.toISOString() + '</div>');

    // End.
    table += divcell;

    // If there is end time...
    if (connections[i].end) {
      table += connections[i].end.toISOString();
    }

    table += '</div>';

    // Time last packet.
    table += (divcell + connections[i].timeLastPacket.toISOString() + '</div>');

    // Client IP.
    table += (divcell + connections[i].clientIp);

    // If the client's hostname is available...
    if (connections[i].clientHostname) {
      table += (' (' + connections[i].clientHostname + ')');
    }

    table += '</div>';

    // Client port.
    table += (divcell + connections[i].clientPort + '</div>');

    // Server IP.
    table += (divcell + connections[i].serverIp);

    // If the server's hostname is available...
    if (connections[i].serverHostname) {
      table += (' (' + connections[i].serverHostname + ')');
    }

    table += '</div>';

    // Server port.
    table += (divcell + connections[i].serverPort + '</div>');

    // Client payload.
    table += (divcell + connections[i].clientPayload + '</div>');

    // Server payload.
    table += (divcell + connections[i].serverPayload + '</div>');

    // Number of bytes transferred by the client.
    table += (divcell + connections[i].transferredClient + '</div>');

    // Number of bytes transferred by the server.
    table += (divcell + connections[i].transferredServer + '</div>');

    // End row.
    table += '</div>';
  }

  // End table.
  table += '</div>';

  // Set table.
  document.getElementById('all-connections').innerHTML = table;

  // Add event listeners.
  for (let i = 0; i < connections.length; i++) {
    // Add event listener.
    document.getElementById(getAllConnectionsRowId(i)).
             addEventListener('click', () => {onConnection(i)}, false);
  }
}

function onConnection(idx)
{
  let conn = connections[idx];

  // Build table with a single connection.
  let table = '<div class="table">';

  // Start of header.
  table += '<div class="heading">';

  table += '<div class="cell">Timestamp</div>';
  table += '<div class="cell">Client IP';

  // If the client's hostname is available...
  if (conn.clientHostname) {
    table += (' (' + conn.clientHostname + ')');
  }

  table += '</div>';

  table += '<div class="cell">Client port</div>';
  table += '<div class="cell">Server IP';

  // If the server's hostname is available...
  if (conn.serverHostname) {
    table += (' (' + conn.serverHostname + ')');
  }

  table += '</div>';

  table += '<div class="cell">Server port</div>';
  table += '<div class="cell">Direction</div>';
  table += '<div class="cell">Payload</div>';

  // End of header.
  table += '</div>';

  // Add payloads.
  for (let i = 0; i < conn.payloadEvents.length; i++) {
    // Start row.
    table += '<div class="row">';

    const divcell = '<div class="cell">';

    // Timestamp.
    table += (divcell +
              conn.payloadEvents[i].timestamp.toISOString() +
              '</div>');

    // Client IP.
    table += (divcell + conn.clientIp + '</div>');

    // Client port.
    table += (divcell + conn.clientPort + '</div>');

    // Server IP.
    table += (divcell + conn.serverIp + '</div>');

    // Server port.
    table += (divcell + conn.serverPort + '</div>');

    // Direction.
    table += divcell;

    // Client to server?
    if (conn.payloadEvents[i].saddr === conn.clientIp) {
      table += 'Client -> Server';
    } else {
      table += 'Server -> Client';
    }

    table += '</div>';

    // Payload.
    table += (divcell + conn.payloadEvents[i].payload + '</div>');

    // End row.
    table += '</div>';
  }

  // End table.
  table += '</div>';

  // Set table.
  document.getElementById('single-connection').innerHTML = table;

  showConnectionGraphic(conn);
}

function onDnsClient()
{
}

// Height of the canvas.
let canvasHeight;

const startX = 100;
const startY = 100;

function translateY(y)
{
  return canvasHeight - y;
}

function showConnectionGraphic(conn)
{
  let canvas = document.getElementById('connection-graphic');
  let ctx = canvas.getContext('2d');

  if (ctx) {
    // Clear canvas.
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const graphic = new Graphic();

    graphic.setYOrigin(0);

    const count = conn.payloadEvents.length;

    // Start client set of points.
    graphic.startSet('client', 'red');

    // Add client points.
    for (let i = 0; i < count; i++) {
      // Client to server?
      if (conn.payloadEvents[i].saddr === conn.clientIp) {
        graphic.addPoint(conn.payloadEvents[i].timestamp.getTime(),
                         conn.payloadEvents[i].payload);
      }
    }

    // End set of points.
    graphic.endSet();

    // Start server set of points.
    graphic.startSet('server', 'blue');

    // Add server points.
    for (let i = 0; i < count; i++) {
      // Server to client?
      if (conn.payloadEvents[i].saddr === conn.serverIp) {
        graphic.addPoint(conn.payloadEvents[i].timestamp.getTime(),
                         conn.payloadEvents[i].payload);
      }
    }

    // End set of points.
    graphic.endSet();

    // Draw graphic.
    graphic.draw(ctx,
                 'timestamp',
                 'payload',
                 0,
                 0,
                 canvas.width,
                 canvas.height);
  }
}

class Axis {
  // Constructor.
  constructor()
  {
    // Points.
    this.points = new Set();

    // Minimum value.
    this.min = null;

    // Maximum value.
    this.max = null;
  }

  // Add point.
  addPoint(point)
  {
    // Add point.
    this.points.add(point);

    // Minimum point?
    if ((this.min === null) || (point < this.min)) {
      this.min = point;
    }

    // Maximum point?
    if ((this.max === null) || (point > this.max)) {
      this.max = point;
    }
  }

  // Compute ticks.
  computeTicks(length, minSpacing)
  {
    this.ticks = [];

    // If there is at least one point...
    if (this.points.size > 0) {
      // Save range.
      this.range = this.max - this.min;

      // Save length.
      this.length = length - 1;

      // Convert set to an array.
      let points = Array.from(this.points);

      // Sort array.
      points.sort(function(a, b) {
        return a - b;
      });

      // Insert first tick.
      this.ticks.push({coord: 0, value: points[0]});

      if (this.points.size > 1) {
        // Index of the last point.
        const idxLastPoint = points.length - 1;

        let prev = 0;

        // For each intermediate point...
        for (let i = 1; i < idxLastPoint; i++) {
          const coord = this.computeCoordinate(points[i]);

          // If the spacing is big enough...
          if ((coord - prev >= minSpacing) &&
              (this.length - coord >= minSpacing)) {
            this.ticks.push({coord: coord, value: points[i]});

            prev = coord;
          }
        }

        // Insert last tick.
        this.ticks.push({coord: this.length, value: points[idxLastPoint]});
      }
    }
  }

  // Compute coordinate.
  computeCoordinate(point)
  {
    return Math.trunc(((point - this.min) * this.length) / this.range);
  }
}

class Graphic {
  // Constructor.
  constructor()
  {
    // Create x-axis.
    this.xaxis = new Axis();

    // Create y-axis.
    this.yaxis = new Axis();

    // List of set of points.
    this.points = [];

    // Current set of points.
    this.currentSet = [];

    this.TICK_LENGTH = 5;
  }

  // Set X origin.
  setXOrigin(x)
  {
    this.xaxis.addPoint(x);
  }

  // Set Y origin.
  setYOrigin(y)
  {
    this.yaxis.addPoint(y);
  }

  // Start set of points.
  startSet(name, color)
  {
    this.currentSet = {name: name, color: color, points: []};
  }

  // End set of points.
  endSet()
  {
    // If the current set of points is not empty...
    if (this.currentSet.points.length > 0) {
      // Sort points.
      this.currentSet.points.sort(function(p1, p2) {
        return p1.x - p2.x;
      });

      // Add current set of points.
      this.points.push(this.currentSet);
    }
  }

  // Add point.
  addPoint(x, y)
  {
    this.xaxis.addPoint(x);
    this.yaxis.addPoint(y);

    this.currentSet.points.push({x: x, y: y});
  }

  // Draw graphic.
  draw(ctx, xname, yname, x, y, width, height)
  {
    const MARGIN = {TOP: 30, BOTTOM: 110, LEFT: 100, RIGHT: 75};

    // Save context.
    this.ctx = ctx;

    // Save X origin.
    this.x = x + MARGIN.LEFT;

    // Save Y origin.
    this.y = y + MARGIN.TOP;

    // Save width.
    this.width = width - (MARGIN.LEFT + MARGIN.RIGHT);

    // Save height.
    this.height = height - (MARGIN.TOP + MARGIN.BOTTOM);

    // Draw axes.
    this.drawAxes(xname, yname, MARGIN);

    // Draw points.
    this.drawPoints();
  }

  // Draw axes.
  drawAxes(xname, yname, MARGIN)
  {
    const origin = {x: this.translateX(0), y: this.translateY(0)};

    this.ctx.fillStyle = 'black';

    // Start drawing axes.
    this.ctx.beginPath();

    // Draw x-axis.
    this.ctx.moveTo(origin.x, origin.y);
    this.ctx.lineTo(this.translateX(this.width), origin.y);

    // Draw y-axis.
    this.ctx.moveTo(origin.x, origin.y);
    this.ctx.lineTo(origin.x, this.translateY(this.height));

    this.ctx.stroke();

    // Draw X ticks.
    this.drawXTicks();

    // Draw Y ticks.
    this.drawYTicks();

    this.ctx.textBaseline = 'middle';
    this.ctx.textAlign = 'left';

    // Write name of the x-axis.
    this.ctx.fillText(xname,
                      this.translateX(this.width),
                      origin.y + (MARGIN.BOTTOM / 2));

    this.ctx.textAlign = 'right';

    // Write name of the y-axis.
    this.ctx.fillText(yname,
                      origin.x,
                      this.translateY(this.height) -
                      Math.trunc(MARGIN.TOP / 2));
  }

  // Draw points.
  drawPoints()
  {
    const origin = {x: this.translateX(0), y: this.translateY(0)};

    const LEGEND = {WIDTH: 8, HEIGHT: 8};

    const legendX = this.translateX(this.width) + 10;
    let legendY = this.translateY(this.height);

    // For each set...
    for (let i = 0; i < this.points.length; i++) {
      this.ctx.fillStyle = this.points[i].color;

      this.ctx.beginPath();

      this.ctx.moveTo(origin.x, origin.y);

      let x = null;
      let sumY;
      let npoints = 0;

      // For each point...
      for (let j = 0; j < this.points[i].points.length; j++) {
        const tmpx = this.xaxis.computeCoordinate(this.points[i].points[j].x);
        const tmpy = this.yaxis.computeCoordinate(this.points[i].points[j].y);

        // If not the first point...
        if (x !== null) {
          // New point?
          if (tmpx !== x) {
            // Draw a line to the previous point.
            this.ctx.lineTo(this.translateX(x),
                            this.translateY(Math.trunc(sumY / npoints)));

            // Save new point.
            x = tmpx;
            sumY = tmpy;

            npoints = 1;
          } else {
            sumY += tmpy;
            npoints++;
          }
        } else {
          x = tmpx;
          sumY = tmpy;

          npoints = 1;
        }
      }

      if (x !== null) {
        const tmpx = this.translateX(x);

        // Draw a line to the point.
        this.ctx.lineTo(tmpx, this.translateY(Math.trunc(sumY / npoints)));

        this.ctx.lineTo(tmpx, origin.y);
        this.ctx.moveTo(origin.x, origin.y);

        this.ctx.closePath();

        // Fill polygon.
        this.ctx.fill();

        // Draw legend.
        this.ctx.fillRect(legendX, legendY, LEGEND.WIDTH, LEGEND.HEIGHT);

        this.ctx.textAlign = 'left';
        this.ctx.textBaseline = 'middle';

        this.ctx.fillText(this.points[i].name,
                          legendX + LEGEND.WIDTH + 4,
                          legendY + Math.trunc(LEGEND.HEIGHT / 2));

        legendY += 15;
      }
    }
  }

  // Draw X ticks.
  drawXTicks()
  {
    const X_MIN_TICK_SPACING = 20;

    // Compute ticks in the x-axis.
    this.xaxis.computeTicks(this.width, X_MIN_TICK_SPACING);

    this.ctx.textBaseline = 'middle';
    this.ctx.textAlign = 'right';

    // For each tick...
    for (let i = 0; i < this.xaxis.ticks.length; i++) {
      const x = this.translateX(this.xaxis.ticks[i].coord);
      const y = this.translateY(0);

      // Save context.
      this.ctx.save();

      // Translate context.
      this.ctx.translate(x, y + this.TICK_LENGTH + 10);

      // Rotate context.
      this.ctx.rotate(-Math.PI / 4);

      const date = new Date(this.xaxis.ticks[i].value);

      this.ctx.fillText(date.toISOString(), 0, 0);

      //this.ctx.fillText(this.xaxis.ticks[i].value, 0, 0);

      // Restore context.
      this.ctx.restore();

      this.ctx.beginPath();

      // Draw horizontal tick.
      this.ctx.moveTo(x, y);
      this.ctx.lineTo(x, y + this.TICK_LENGTH);

      this.ctx.stroke();
    }
  }

  // Draw Y ticks.
  drawYTicks()
  {
    const Y_MIN_TICK_SPACING = 20;

    // Compute ticks in the x-axis.
    this.yaxis.computeTicks(this.height, Y_MIN_TICK_SPACING);

    this.ctx.textBaseline = 'middle';
    this.ctx.textAlign = 'right';

    // For each tick...
    for (let i = 0; i < this.yaxis.ticks.length; i++) {
      const x = this.translateX(0);
      const y = this.translateY(this.yaxis.ticks[i].coord);

      this.ctx.fillText(this.yaxis.ticks[i].value, x - this.TICK_LENGTH - 5, y);

      this.ctx.beginPath();

      // Draw vertical tick.
      this.ctx.moveTo(x - this.TICK_LENGTH, y);
      this.ctx.lineTo(x, y);

      this.ctx.stroke();
    }
  }

  translateX(x)
  {
    return this.x + x;
  }

  translateY(y)
  {
    return this.y + this.height - y;
  }
}

// Function: getAllConnectionsRowId
// Description: receives as input a row number from the 'all-connections' table
// and returns the id attribute of the row.
// Parameter: row number.
// Returns: the id attribute.
function getAllConnectionsRowId(idx)
{
  return 'connections-' + idx;
}

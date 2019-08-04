<html>
  <head>
    <title>Test</title>
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
<?php

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Constants.                                                                 //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Database file.
const DATABASE = "/home/guido/programming/c++/netmon/php/events.db";

// Name of the event tables.
const TABLES = array("icmp", "udp", "dns", "tcp_begin", "tcp_data", "tcp_end");


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Functions.                                                                 //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Function: parseTimestamp
// Description: receives as input a timestamp with the format
// 'YYYY/MM/DD hh:mm:ss.uuuuuu' and returns as output the timestamp as the
// number of microseconds since 1970-01-01 00:00:00 +0000 (UTC).
// Parameter: timestamp with the format 'YYYY/MM/DD hh:mm:ss.uuuuuu'.
// Returns: in case of success: timestamp as the number of microseconds since
// 1970-01-01 00:00:00 +0000 (UTC); 0: otherwise.
function parseTimestamp($timestamp)
{
  // Perform regular expression match.
  preg_match("/(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2}).(\d{6})/",
             $timestamp,
             $matches);

  // Success?
  if (count($matches) === 8) {
    $year = $matches[1];
    $mon  = $matches[2];
    $mday = $matches[3];
    $hour = $matches[4];
    $min  = $matches[5];
    $sec  = $matches[6];
    $usec = $matches[7];

    return (mktime($hour, $min, $sec, $mon, $mday, $year) * 1000000) + $usec;
  } else {
    return 0;
  }
}

// Function: timestampToString
// Description: receives as input a timestamp as the number of microseconds
// since 1970-01-01 00:00:00 +0000 (UTC) and returns as output the timestamp
// with the format 'YYYY/MM/DD hh:mm:ss.uuuuuu'.
// Parameter: timestamp as the number of microseconds since
// 1970-01-01 00:00:00 +0000 (UTC).
// Returns: timestamp with the format 'YYYY/MM/DD hh:mm:ss.uuuuuu'.
function timestampToString($timestamp)
{
  $tm = localtime($timestamp / 1000000);

  $year = 1900 + $tm[5];
  $mon  =    1 + $tm[4];
  $mday =        $tm[3];
  $hour =        $tm[2];
  $min  =        $tm[1];
  $sec  =        $tm[0];

  $usec = $timestamp % 1000000;

  return sprintf("%04u/%02u/%02u %02u:%02u:%02u.%06u",
                 $year,
                 $mon,
                 $mday,
                 $hour,
                 $min,
                 $sec,
                 $usec);
}

// Function: getMinimumTimestamp
// Description: returns the minimum timestamp of the tables:
//   icmp
//   udp
//   dns
//   tcp_begin
//   tcp_data
//   tcp_end
// Parameter: database handle.
// Returns: the minimum timestamp of the aforementioned tables.
function getMinimumTimestamp($db)
{
  $timestamp = PHP_INT_MAX;

  // For each table...
  foreach (TABLES as $table) {
    $tmpTimestamp = $db->querySingle(sprintf("SELECT MIN(timestamp) from %s",
                                             $table));

    // If the timestamp is smaller...
    if ($tmpTimestamp < $timestamp) {
      $timestamp = $tmpTimestamp;
    }
  }

  return $timestamp;
}

// Function: getMaximumTimestamp
// Description: returns the maximum timestamp of the tables:
//   icmp
//   udp
//   dns
//   tcp_begin
//   tcp_data
//   tcp_end
// Parameter: database handle.
// Returns: the maximum timestamp of the aforementioned tables.
function getMaximumTimestamp($db)
{
  $timestamp = 0;

  // For each table...
  foreach (TABLES as $table) {
    $tmpTimestamp = $db->querySingle(sprintf("SELECT MAX(timestamp) from %s",
                                             $table));

    // If the timestamp is bigger...
    if ($tmpTimestamp > $timestamp) {
      $timestamp = $tmpTimestamp;
    }
  }

  return $timestamp;
}

// Function: showIcmp
// Description: shows the "ICMP" table.
// Parameter: database handle.
function showIcmp($db)
{
  // Print table header.
  echo("<table>" .
         "<tr>" .
           "<th>Timestamp</th>" .
           "<th>Source address</th>" .
           "<th>Destination address</th>" .
           "<th>Source hostname</th>" .
           "<th>Destination hostname</th>" .
           "<th>ICMP type</th>" .
           "<th>ICMP code</th>" .
           "<th>Transferred</th>" .
         "</tr>");

  $results = $db->query("select * from icmp");

  // For each row...
  while ($row = $results->fetchArray()) {
    echo("<tr>");

    echo("<td>" . timestampToString($row['timestamp']) . "</td>");
    echo("<td>" . $row['source_address']               . "</td>");
    echo("<td>" . $row['destination_address']          . "</td>");
    echo("<td>" . $row['source_hostname']              . "</td>");
    echo("<td>" . $row['destination_hostname']         . "</td>");
    echo("<td>" . $row['icmp_type']                    . "</td>");
    echo("<td>" . $row['icmp_code']                    . "</td>");
    echo("<td>" . $row['transferred']                  . "</td>");

    echo("</tr>");
  }

  echo("</table>");
}

// Function: showUdp
// Description: shows the "UDP" table.
// Parameter: database handle.
function showUdp($db)
{
  // Print table header.
  echo("<table>" .
         "<tr>" .
           "<th>Timestamp</th>" .
           "<th>Source address</th>" .
           "<th>Destination address</th>" .
           "<th>Source hostname</th>" .
           "<th>Destination hostname</th>" .
           "<th>Source port</th>" .
           "<th>Destination port</th>" .
           "<th>Transferred</th>" .
         "</tr>");

  $results = $db->query("select * from udp");

  // For each row...
  while ($row = $results->fetchArray()) {
    echo("<tr>");

    echo("<td>" . timestampToString($row['timestamp']) . "</td>");
    echo("<td>" . $row['source_address']               . "</td>");
    echo("<td>" . $row['destination_address']          . "</td>");
    echo("<td>" . $row['source_hostname']              . "</td>");
    echo("<td>" . $row['destination_hostname']         . "</td>");
    echo("<td>" . $row['source_port']                  . "</td>");
    echo("<td>" . $row['destination_port']             . "</td>");
    echo("<td>" . $row['transferred']                  . "</td>");

    echo("</tr>");
  }

  echo("</table>");
}

// Function: showDns
// Description: shows the "DNS" table.
// Parameter: database handle.
function showDns($db)
{
  // Print table header.
  echo("<table>" .
         "<tr>" .
           "<th>Timestamp</th>" .
           "<th>Source address</th>" .
           "<th>Destination address</th>" .
           "<th>Source port</th>" .
           "<th>Destination port</th>" .
           "<th>Transferred</th>" .
           "<th>Query type</th>" .
           "<th>Domain</th>" .
           "<th>IP address</th>" .
         "</tr>");

  $results = $db->query("select * from dns");

  // For each row...
  while ($row = $results->fetchArray()) {
    echo("<tr>");

    echo("<td>" . timestampToString($row['timestamp']) . "</td>");
    echo("<td>" . $row['source_address']               . "</td>");
    echo("<td>" . $row['destination_address']          . "</td>");
    echo("<td>" . $row['source_port']                  . "</td>");
    echo("<td>" . $row['destination_port']             . "</td>");
    echo("<td>" . $row['transferred']                  . "</td>");
    echo("<td>" . $row['query_type']                   . "</td>");
    echo("<td>" . $row['domain']                       . "</td>");
    echo("<td>" . $row['ip_address']                   . "</td>");

    echo("</tr>");
  }

  echo("</table>");
}

// Function: showTcpBegin
// Description: shows the "Begin TCP connection" table.
// Parameter: database handle.
function showTcpBegin($db)
{
  // Print table header.
  echo("<table>" .
         "<tr>" .
           "<th>Timestamp</th>" .
           "<th>Source address</th>" .
           "<th>Destination address</th>" .
           "<th>Source hostname</th>" .
           "<th>Destination hostname</th>" .
           "<th>Source port</th>" .
           "<th>Destination port</th>" .
         "</tr>");

  $results = $db->query("select * from tcp_begin");

  // For each row...
  while ($row = $results->fetchArray()) {
    echo("<tr>");

    echo("<td>" . timestampToString($row['timestamp']) . "</td>");
    echo("<td>" . $row['source_address']               . "</td>");
    echo("<td>" . $row['destination_address']          . "</td>");
    echo("<td>" . $row['source_hostname']              . "</td>");
    echo("<td>" . $row['destination_hostname']         . "</td>");
    echo("<td>" . $row['source_port']                  . "</td>");
    echo("<td>" . $row['destination_port']             . "</td>");

    echo("</tr>");
  }

  echo("</table>");
}

// Function: showTcpData
// Description: shows the "TCP data" table.
// Parameter: database handle.
function showTcpData($db)
{
  // Print table header.
  echo("<table>" .
         "<tr>" .
           "<th>Timestamp</th>" .
           "<th>Source address</th>" .
           "<th>Destination address</th>" .
           "<th>Source hostname</th>" .
           "<th>Destination hostname</th>" .
           "<th>Source port</th>" .
           "<th>Destination port</th>" .
           "<th>Creation</th>" .
           "<th>Payload</th>" .
         "</tr>");

  $results = $db->query("select * from tcp_data");

  // For each row...
  while ($row = $results->fetchArray()) {
    echo("<tr>");

    echo("<td>" . timestampToString($row['timestamp']) . "</td>");
    echo("<td>" . $row['source_address']               . "</td>");
    echo("<td>" . $row['destination_address']          . "</td>");
    echo("<td>" . $row['source_hostname']              . "</td>");
    echo("<td>" . $row['destination_hostname']         . "</td>");
    echo("<td>" . $row['source_port']                  . "</td>");
    echo("<td>" . $row['destination_port']             . "</td>");
    echo("<td>" . timestampToString($row['creation'])  . "</td>");
    echo("<td>" . $row['payload']                      . "</td>");

    echo("</tr>");
  }

  echo("</table>");
}

// Function: showTcpEnd
// Description: shows the "End TCP connection" table.
// Parameter: database handle.
function showTcpEnd($db)
{
  // Print table header.
  echo("<table>" .
         "<tr>" .
           "<th>Timestamp</th>" .
           "<th>Source address</th>" .
           "<th>Destination address</th>" .
           "<th>Source hostname</th>" .
           "<th>Destination hostname</th>" .
           "<th>Source port</th>" .
           "<th>Destination port</th>" .
           "<th>Creation</th>" .
           "<th>Transferred client</th>" .
           "<th>Transferred server</th>" .
         "</tr>");

  $results = $db->query("select * from tcp_end");

  // For each row...
  while ($row = $results->fetchArray()) {
    echo("<tr>");

    echo("<td>" . timestampToString($row['timestamp']) . "</td>");
    echo("<td>" . $row['source_address']               . "</td>");
    echo("<td>" . $row['destination_address']          . "</td>");
    echo("<td>" . $row['source_hostname']              . "</td>");
    echo("<td>" . $row['destination_hostname']         . "</td>");
    echo("<td>" . $row['source_port']                  . "</td>");
    echo("<td>" . $row['destination_port']             . "</td>");
    echo("<td>" . timestampToString($row['creation'])  . "</td>");
    echo("<td>" . $row['transferred_client']           . "</td>");
    echo("<td>" . $row['transferred_server']           . "</td>");

    echo("</tr>");
  }

  echo("</table>");
}

  // Open database for reading.
  $db = new SQLite3(DATABASE, SQLITE3_OPEN_READONLY);

  echo("Minimum timestamp: " . timestampToString(getMinimumTimestamp($db)) . "<br>");
  echo("Maximum timestamp: " . timestampToString(getMaximumTimestamp($db)) . "<br>");

  //showIcmp($db);
  //showUdp($db);
  //showDns($db);
  //showTcpBegin($db);
  //showTcpData($db);
  showTcpEnd($db);
?>

  </body>
</html>

require("dotenv").config();

const { exec } = require("child_process");
const express = require("express");
const app = express();

app.set("trust proxy", "loopback");

app.listen(process.env.PORT || 8080, () => {
  console.log("Web server listening");
});

app.use(express.static("public"));

const ratelimits = new Map();

setInterval(() => ratelimits.clear(), 60 * 1000);

app.get("/:domain", (req, res) => {
  const domain = req.params.domain;
  if (domain === "favicon.ico") return res.status(404).header("Content-type", "text/plain").send("Not found");
  console.log("Querying", domain, "for", req.ip);
  ratelimits.set(req.ip, (ratelimits.get(req.ip) ?? 0) + 1);
  if (ratelimits.get(req.ip) >= 5) {
    res.status(429).header("Content-type", "text/plain").send("Requests limited to 5 per minute");
    return;
  }
  if (/^[a-z0-9_-]+\.[a-z0-9_-]+$/i.test(domain)) {
    exec(`whois '${domain}'`, {
      timeout: 10 * 1000,
    }, (err, stdout, stderr) => {
      if (stdout.trim() === "No whois server is known for this kind of object.") {
        console.log("Invalid TLD", domain);
        res.status(400).header("Content-type", "text/plain").send("Invalid TLD");
      } else if (err) {
        console.error("Failed to query", domain, err, stdout.toString(), stderr.toString());
        res.status(500).header("Content-type", "text/plain").send("Server error");
      } else {
        console.log("Succesfully queried", domain);
        res.status(200).header("Content-type", "text/plain").send(stdout.toString());
      }
    });
  } else {
    res.status(400).header("Content-type", "text/plain").send("Unacceptable domain");
  }
});

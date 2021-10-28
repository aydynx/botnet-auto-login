const child = require("child_process");
const totp = require("totp-generator");
const config = require("./config.json");
const mappings = require("./mappings.json");

if (config.connection.protocol === "ssh") {
    var connection = child.spawn("ssh", [config.connection.ip, "-p", config.connection.port, "-l", config.credentials.username]);
    connection.stdin.write(config.credentials.password);
} else if (config.connection.protocol === "telnet") {
    var connection = child.spawn("telnet", [config.connection.ip, config.connection.port]);
} else {
    console.log("invalid protocol");
}

connection.stdin.write("\n");
connection.stdout.pipe(process.stdout);
connection.stderr.pipe(process.stderr);
process.stdin.pipe(connection.stdin);

let state = 0;
let buffer = "";
connection.stdout.on("data", (data) => {
    const lines = data.toString().split(/\r?\n/);
    for (const line of lines) {
        if (state === 0 && line.toLowerCase().includes("captcha")) {
            state = 1;
        } else if (state === 1) {
            if (line.trim() === "") {
                state = 2;
            }
        } else if (state === 2) {
            if (line.trim() === "" && buffer.trim()) {
                let offset = 1;
                for (let i = 0; i < 5; i++) {
                    let letter = captchaParse(offset, buffer);
                    connection.stdin.write(letter);
                    offset += 15;
                    while (captchaParse(offset, buffer) === undefined) {
                        offset--;
                    }
                }
                if (line.toLowerCase().includes("2fa" || "authenticator" || "mfa")) {
                    connection.stderr.write(totp(config.mfa.token) + "\n");
                }
                if (config.connection.protocol === "telnet") {
                    connection.stdin.write("\n" + config.credentials.username + "\n" + config.credentials.password + "\n");
                }
                state = 3;
            } else if (line.trim()) {
                buffer += line + "\n";
            }
        }
    }
});


function captchaParse(x, s) {
    const lines = s.split("\n");
    outer: for (const letter in mappings) {
        const letterLines = mappings[letter].split("\n");
        for (let i = 0; i < letterLines.length; i++) {
            if (!lines[i].slice(x).startsWith(letterLines[i])) {
                continue outer;
            }
        }
        return letter;
    }
}

connection.on("close", (code) => {
    console.log(`child process exited with code ${code}`);
});
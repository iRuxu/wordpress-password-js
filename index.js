const crypto = require('crypto');
const {
    md5,
    substr,
    strlen,
} = require("locutus/php/strings");
const { uniqid, pack } = require("locutus/php/misc");
const { rand } = require("locutus/php/math");
const { microtime } = require("locutus/php/datetime");

const ITOA64_TABLE = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

class PasswordHash {

    hash(password, setting) {

        let output = "*0";
        if (substr(setting, 0, 2) == output) output = "*1";

        const id = substr(setting, 0, 3);

        if (id != "$P$" && id != "$H$") return output;

        let count_log2 = ITOA64_TABLE.indexOf(setting[3]);

        if (count_log2 < 7 || count_log2 > 30) {

            return "*";
        }

        let count = 1 << count_log2;

        let salt = setting.substr(4, 8);

        let hasher = crypto.createHash("md5");

        hasher.update(`${salt}${password}`);

        let hash = hasher.digest();

        do {
            hasher = crypto.createHash("md5");
            hasher.update(hash);
            hasher.update(password);
            hash = hasher.digest();
        }
        while (--count);

        return `${setting.substr(0, 12)}${this._encode64(hash, 16)}`;
    }

    _encode64(input, count){

        let output = "";

        let i = 0;

        do {

            let value = input[i++];

            output += ITOA64_TABLE[value & 0x3f];

            if (i < count) {

                value |= input[i] << 8;
            }

            output += ITOA64_TABLE[(value >> 6) & 0x3f];

            if (i++ >= count) {

                break;
            }

            if (i < count) {

                value |= input[i] << 16;
            }

            output += ITOA64_TABLE[(value >> 12) & 0x3f];

            if (i++ >= count) {

                break;
            }

            output += ITOA64_TABLE[(value >> 18) & 0x3f];

        } while (i < count);

        return output;
    }

    _random(count){
        let output = "";
        let state = microtime() + uniqid(rand(), true);
        for (let i = 0; i < count; i += 16) {
            state = md5(microtime() + state);
            output += pack("H*", md5(state));
        }
        output = substr(output, 0, count);
        let buf = Buffer.from(output).toString("binary")
        return buf;
    }

    _gensalt(input){
        let output = "$P$";
        output += ITOA64_TABLE[Math.min(8 + 5,30)];
        output += this._encode64(input, 6);
        return output;
    }

    build(password){
        if (strlen(password) > 4096) {
            return "*";
        }

        let random = this._random(6);
        let hash = this.hash(password, this._gensalt(random));
        if (strlen(hash) == 34) return hash;

        return "*";
    }

    check(password, storedHash){

        if (password.length > 4096) {

            return false;
        }

        let hash = this.hash(password, storedHash);

        if (hash === "*") {
            return false;
        }

        return hash === storedHash;
    }
}

module.exports = PasswordHash
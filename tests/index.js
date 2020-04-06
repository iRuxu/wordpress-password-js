const PasswordHash = require('../index');
const hasher = new PasswordHash()

var x = hasher.build('123456')
var y = hasher.check('123456',x)
console.log(x,y)
# Wordpress Password

Create and verify wordpress password @node.js  
用于wordpress密码创建与校验的node.js版本，用于任何平台

特别说明：基于***PHP版本 v7+***

# Usage
## Install
```
npm install --save wordpress-password-js
```

## Import
```
const PasswordHash = require('wordpress-password-js');
const hasher = new PasswordHash()

//create a new pwd
var x = hasher.build('123456')
//verify an old pwd
var y = hasher.check('123456',x)
console.log(x,y)
```

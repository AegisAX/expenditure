const assert = require('node:assert/strict');
const fs = require('fs');
const vm = require('vm');
let settings = {smtp_host:'mail.example.com',smtp_port:'587',smtp_user:'kumoh',smtp_pass:'test',mail_from_name:'금오공고 총동문회 사무국',mail_from_address:''};
const messages=[];
const sandbox={module:{exports:{}},console:{log(){},warn(){},error(){}},require(name){
 if(name==='./db')return {getSettings:async()=>({...settings})};
 if(name==='nodemailer')return {createTransport:()=>({close(){},sendMail(message,cb){messages.push(message);cb(null,{messageId:'test',response:'250 queued'});}})};
 return require(name);
}};
vm.runInNewContext(fs.readFileSync(require.resolve('../helpers/email'),'utf8'),sandbox);
const mail=sandbox.module.exports;
(async()=>{
 await mail.initTransporter();
 assert.equal((await mail.sendEmail('recipient@example.com','test','test')).success,false);
 assert.equal(messages.length,0);
 settings.mail_from_address='kumoh@example.com';await mail.reloadTransporter();
 assert.equal((await mail.sendEmail('recipient@example.com','test','test')).success,true);
 assert.equal(messages[0].from.address,'kumoh@example.com');
 assert.equal(messages[0].from.name,settings.mail_from_name);
 settings.mail_from_address='';settings.smtp_user='legacy@example.com';await mail.reloadTransporter();
 assert.equal((await mail.sendEmail('recipient@example.com','test','test')).success,true);
 assert.equal(messages[1].from.address,'legacy@example.com');
 settings.mail_from_address='bad\r\nBcc: someone@example.com';await mail.reloadTransporter();
 assert.equal((await mail.sendEmail('recipient@example.com','test','test')).success,false);
 assert.equal(messages.length,2);
 console.log('PASS: 잘못된 From 차단, 로그인 계정과 발신 주소 분리, 이메일 계정 호환, 헤더 주입 차단 (실제 메일 발송 없음)');
})().catch(e=>{console.error(e);process.exitCode=1;});

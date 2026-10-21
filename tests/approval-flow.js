// 실제 DB와 첨부파일을 사용하지 않는 API 회귀 검증.
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const root = path.resolve(__dirname, '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'approval-flow-'));
process.chdir(temp);
fs.mkdirSync('db');
const express = require('express');
const db = require('../database');
const run = (sql, args=[]) => new Promise((resolve,reject)=>db.run(sql,args,function(e){e?reject(e):resolve(this);}));
const get = (sql,args=[])=>new Promise((resolve,reject)=>db.get(sql,args,(e,r)=>e?reject(e):resolve(r)));
const users = {
 owner:{email:'owner@test.kr',name:'기안자',position:'회원',role:'User'},
 middle:{email:'middle@test.kr',name:'중간담당',position:'기획국장',role:'User'},
 secretary:{email:'sec@test.kr',name:'사무총장',position:'사무총장',role:'User'},
 president:{email:'pres@test.kr',name:'회장',position:'총동문회장',role:'User'},
 finance:{email:'fin@test.kr',name:'재무',position:'재무국장',role:'User'},
 other:{email:'other@test.kr',name:'다른회원',position:'회원',role:'User'}
};
const app=express();
app.set('view engine','ejs'); app.set('views',path.join(root,'views'));
app.use(express.json());
app.use((req,res,next)=>{req.session={user:users[req.headers['x-user']||'owner']};res.locals.csrfToken='test';next();});
app.use(require('../routes/approval'));
let server;
(async()=>{
 await get('SELECT id FROM users LIMIT 1'); // 초기 스키마 작업 이후 실행
 for(const u of Object.values(users)) await run("INSERT INTO users(email,name,position,status,role) VALUES(?,?,?,'Approved','User')",[u.email,u.name,u.position]);
 server=app.listen(0,'127.0.0.1'); await new Promise(r=>server.once('listening',r));
 const base=`http://127.0.0.1:${server.address().port}`;
 async function request(url,user='owner',body) {
  const res=await fetch(base+url,{method:body?'POST':'GET',headers:{'x-user':user,...(body instanceof FormData?{}:{'Content-Type':'application/json'})},body:body?(body instanceof FormData?body:JSON.stringify(body)):undefined});
  const text=await res.text();return {code:res.status,text,data:()=>JSON.parse(text)};
 }
 async function submit(docNum,middle='',type='G',user='owner',status='제출완료') {
  const f=new FormData();for(const [k,v] of Object.entries({docNum,docType:type,status,subject:'테스트',bodyContent:'<p>내용</p>',totalAmount:'100',items:'[]'}))f.set(k,v);
  if(middle!==null)f.set('middleApproverEmail',middle);
  return request('/api/submit',user,f);
 }
 async function doc(email,type='G',user='owner',status='제출완료') {
  const before=await get('SELECT COUNT(*) n FROM approvals');
  const result=await submit('',email,type,user,status);assert.equal(result.code,200,result.text);
  const row=await get('SELECT * FROM approvals ORDER BY rowid DESC LIMIT 1');
  assert.equal((await get('SELECT COUNT(*) n FROM approvals')).n,before.n+1); return row;
 }
 let d=await doc('');assert.equal(d.status,'결재중');assert.equal(d.middleApproverEmail,'');
 assert.equal((await request('/api/approve','secretary',{docNum:d.docNum,action:'REJECT'})).data().status,'Error');
 await request('/api/approve','president',{docNum:d.docNum,action:'APPROVE'});
 assert.equal((await get("SELECT * FROM approvals WHERE status='결재완료'")).docType,'G');
 d=await doc(users.middle.email);assert.equal(d.status,'제출완료');
 assert.equal((await request('/list','middle')).code,200);
 assert.match((await request('/list','middle')).text,/테스트/);
 assert.equal((await request('/form?docNum='+encodeURIComponent(d.docNum),'other')).code,403);
 assert.equal((await request('/form?docNum='+encodeURIComponent(d.docNum),'middle')).code,200);
 assert.equal((await request('/api/lock/acquire','middle',{docNum:d.docNum})).data().status,'Success');
 assert.equal((await request('/api/approve','secretary',{docNum:d.docNum,action:'APPROVE'})).code,403);
 assert.equal((await submit(d.docNum,'','G','other')).code,400);
 await request('/api/approve','middle',{docNum:d.docNum,action:'APPROVE'});
 d=await get('SELECT * FROM approvals WHERE docNum=?',[d.docNum]);assert.equal(d.status,'결재중');assert.equal(d.secName,users.middle.name);
 await request('/api/recall','owner',{docNum:d.docNum});
 await submit(d.docNum,'');assert.equal((await get('SELECT * FROM approvals WHERE docNum=?',[d.docNum])).status,'결재중');
 let legacy=await doc(null,'E','owner','작성중');
 await run('UPDATE approvals SET middleApproverEmail=NULL,status=? WHERE docNum=?',['제출완료',legacy.docNum]);
 await request('/api/approve','secretary',{docNum:legacy.docNum,action:'APPROVE'});
 assert.equal((await get('SELECT * FROM approvals WHERE docNum=?',[legacy.docNum])).status,'결재중');
 d=await doc(users.middle.email,'E');
 await request('/api/approve','middle',{docNum:d.docNum,action:'REJECT'});
 assert.equal((await get('SELECT status FROM approvals WHERE docNum=?',[d.docNum])).status,'반려');
 await submit(d.docNum,users.middle.email,'E');
 await request('/api/approve','middle',{docNum:d.docNum,action:'APPROVE'});
 await request('/api/approve','president',{docNum:d.docNum,action:'APPROVE'});
 d=await get("SELECT * FROM approvals WHERE status='최종결재' ORDER BY rowid DESC LIMIT 1");assert.ok(d);
 await request('/api/approve','finance',{docNum:d.docNum,action:'APPROVE'});
 assert.equal((await get('SELECT status FROM approvals WHERE docNum=?',[d.docNum])).status,'지급완료');
 assert.equal((await submit(d.docNum,'','E')).code,400);
 for(const email of [users.owner.email,users.president.email,'missing@test.kr'])assert.equal((await submit('',email)).code,400);
 d=await doc(users.middle.email,'G','secretary');assert.equal(d.status,'제출완료');
 d=await doc(users.middle.email,'G','president');
 await request('/api/approve','middle',{docNum:d.docNum,action:'APPROVE'});
 const presResult=await request('/api/approve','president',{docNum:d.docNum,action:'APPROVE'});assert.equal(presResult.data().msg,'승인 완료');
 d=await doc('','G','president','작성중');const count=await get('SELECT COUNT(*) n FROM approvals');
 await submit(d.docNum,'','G','president');assert.equal((await get('SELECT COUNT(*) n FROM approvals')).n,count.n);
 assert.equal(await get('SELECT * FROM approvals WHERE docNum=?',[d.docNum]),undefined);
 console.log('PASS: 생략/지정/기존 결재선, 목록·상세·잠금 권한, 반려·회수·재제출, 일반기안 종결, 지급완료, 잘못된 결재자, 회장 임시저장 재제출');
})().then(()=>finish(0),e=>{console.error(e);finish(1)});
function finish(code){if(server)server.close(); db.close(()=>{process.chdir(root);fs.rmSync(temp,{recursive:true,force:true});process.exit(code);});}

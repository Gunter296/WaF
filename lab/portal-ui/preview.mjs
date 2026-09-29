// Dependency-free visual preview. No proxy, database writes, or WAF calls.
import http from 'node:http';
import {readFile} from 'node:fs/promises';
const assets = {'/':'index.html','/index.html':'index.html','/app.js':'app.js','/demo.js':'demo.js','/styles.css':'styles.css'};
const mime = {html:'text/html; charset=utf-8',js:'text/javascript; charset=utf-8',css:'text/css; charset=utf-8'};
http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://127.0.0.1');
  if(url.pathname==='/'&&!url.searchParams.has('preview')){res.writeHead(302,{location:'/?preview=1'}).end();return;}
  const file=assets[url.pathname];
  if(!file||req.method!=='GET'){res.writeHead(404).end('not found');return;}
  try{res.writeHead(200,{'content-type':mime[file.split('.').pop()],'cache-control':'no-store'}).end(await readFile(new URL('./public/'+file,import.meta.url)));}
  catch{res.writeHead(500).end('preview asset unavailable');}
}).listen(8091,'127.0.0.1',()=>console.log('Portal UI preview: http://127.0.0.1:8091/?preview=1'));

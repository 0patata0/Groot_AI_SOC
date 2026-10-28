"""Read bounded members of a public ZIP over strict HTTP byte ranges.

Never falls back to a full download. CRC/member SHA provide selected-file
integrity; this does NOT verify the published checksum of the entire archive.
No extraction paths are accepted from callers or written by this reader.
"""
import http.client,io,re,time,urllib.request,urllib.parse
class RemoteZip(io.RawIOBase):
 def __init__(self,url,size,*,opener=None,chunk=1024*1024,max_transfer=32*1024*1024):
  if urllib.parse.urlsplit(url).scheme!='https':raise ValueError('HTTPS source required')
  if not isinstance(size,int) or size<=0 or chunk<=0:raise ValueError('Invalid source bounds')
  self.url=url;self.size=size;self.position=0;self.chunk=chunk;self.max_transfer=max_transfer;self.transferred=0;self.requested_bytes=0;self.calls=0;self.etag=None;self.last_modified=None;self.cache={};self.opener=opener or urllib.request.urlopen
 def readable(self):return True
 def seekable(self):return True
 def tell(self):return self.position
 def seek(self,offset,whence=0):
  value=offset if whence==0 else self.position+offset if whence==1 else self.size+offset if whence==2 else -1
  if value<0:raise ValueError('Invalid seek')
  self.position=value;return value
 def page(self,start):
  if start in self.cache:return self.cache[start]
  end=min(start+self.chunk,self.size)-1;length=end-start+1
  headers={'Range':f'bytes={start}-{end}','Accept-Encoding':'identity','User-Agent':'SOC-source-provenance/1.0'}
  if self.etag:headers['If-Range']=self.etag
  req=urllib.request.Request(self.url,headers=headers)
  for attempt in range(3):
   if self.requested_bytes+length>self.max_transfer:raise ValueError('Range transfer budget exceeded')
   self.requested_bytes+=length
   try:
    with self.opener(req,timeout=45) as response:
     if response.status!=206:raise ValueError('Server ignored byte range; full download refused')
     actual=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',response.headers.get('Content-Range',''))
     if not actual or tuple(map(int,actual.groups()))!=(start,end,self.size):raise ValueError('Content-Range mismatch')
     etag=response.headers.get('ETag');modified=response.headers.get('Last-Modified')
     if self.calls and (etag!=self.etag or modified!=self.last_modified):raise ValueError('Remote archive changed')
     self.calls+=1;self.etag=etag;self.last_modified=modified
     chunks=[];received=0
     while received<length:
      chunk=response.read(min(65536,length-received))
      if not chunk:break
      chunks.append(chunk);received+=len(chunk);self.transferred+=len(chunk)
     if received!=length:raise OSError(f'Short range response: expected {length}, received {received}')
     data=b''.join(chunks)
    break
   except (OSError,http.client.IncompleteRead) as error:
    if attempt==2:raise OSError('Bounded range retry failed') from error
    time.sleep(attempt+1)
  self.cache[start]=data
  return data
 def read(self,n=-1):
  if n is None or n<0:n=self.size-self.position
  n=min(n,self.size-self.position)
  if n<=0:return b''
  if n>self.max_transfer:raise ValueError('Read exceeds transfer budget')
  result=[]
  while n:
   start=self.position//self.chunk*self.chunk;data=self.page(start);at=self.position-start;take=min(n,len(data)-at)
   if take<=0:raise ValueError('Range cursor mismatch')
   result.append(data[at:at+take]);self.position+=take;n-=take
  return b''.join(result)

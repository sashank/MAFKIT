from pathlib import Path
import struct

MAX_DEX_SIZE=512*1024*1024
MAX_TABLE_ITEMS=5_000_000

def _need(b,o,n):
    if o<0 or n<0 or o+n>len(b): raise ValueError(f'Out-of-bounds DEX read at {o}+{n} (size {len(b)})')
def u16(b,o): _need(b,o,2); return struct.unpack_from('<H',b,o)[0]
def u32(b,o): _need(b,o,4); return struct.unpack_from('<I',b,o)[0]
def signed(x,bits): return x-(1<<bits) if x&(1<<(bits-1)) else x

def uleb(b,o):
    v=0; s=0
    for _ in range(5):
        _need(b,o,1); x=b[o]; o+=1; v|=(x&0x7f)<<s
        if not x&0x80: return v,o
        s+=7
    raise ValueError('ULEB128 too long')

def mutf8_at(b,o):
    _,p=uleb(b,o); e=b.find(b'\0',p)
    if e<0: raise ValueError('Unterminated DEX string')
    return b[p:e].decode('utf-8','replace')

WIDTH={}
def setw(keys,w):
    for k in keys: WIDTH[k]=w
setw(range(0x00,0x02),1); setw([0x02],2); setw([0x03],3); setw([0x04],1); setw([0x05],2); setw([0x06],3); setw([0x07],1); setw([0x08],2); setw([0x09],3)
setw(range(0x0a,0x13),1); setw([0x13],2); setw([0x14],3); setw([0x15],2); setw([0x16],2); setw([0x17],3); setw([0x18],5); setw([0x19],2); setw([0x1a],2); setw([0x1b],3); setw([0x1c],2); setw([0x1d,0x1e],1); setw([0x1f,0x20],2); setw([0x21],1); setw([0x22,0x23],2); setw([0x24,0x25,0x26],3); setw([0x27,0x28],1); setw([0x29],2); setw([0x2a,0x2b,0x2c],3); setw(range(0x2d,0x3e),2); setw(range(0x3e,0x44),1); setw(range(0x44,0x6e),2); setw(range(0x6e,0x73),3); setw([0x73],1); setw(range(0x74,0x79),3); setw(range(0x79,0x7b),1); setw(range(0x7b,0x90),1); setw(range(0x90,0xb0),2); setw(range(0xb0,0xd0),1); setw(range(0xd0,0xd8),2); setw(range(0xd8,0xe3),2); setw(range(0xe3,0xfa),1); setw([0xfa,0xfb],4); setw([0xfc,0xfd],3); setw([0xfe,0xff],2)

class Dex:
    def __init__(self,path):
        self.path=Path(path); size=self.path.stat().st_size
        if size>MAX_DEX_SIZE: raise ValueError(f'DEX exceeds size limit: {size}')
        self.b=self.path.read_bytes(); b=self.b
        if len(b)<0x70 or b[:4] != b'dex\n': raise ValueError('Not a valid DEX header')
        file_size=u32(b,0x20)
        if file_size and file_size>len(b): raise ValueError('DEX header file_size exceeds available bytes')
        self.string_ids_size=u32(b,0x38); self.string_ids_off=u32(b,0x3c)
        self.type_ids_size=u32(b,0x40); self.type_ids_off=u32(b,0x44)
        self.proto_ids_size=u32(b,0x48); self.proto_ids_off=u32(b,0x4c)
        self.method_ids_size=u32(b,0x58); self.method_ids_off=u32(b,0x5c)
        self.class_defs_size=u32(b,0x60); self.class_defs_off=u32(b,0x64)
        for name,n in [('strings',self.string_ids_size),('types',self.type_ids_size),('protos',self.proto_ids_size),('methods',self.method_ids_size),('classes',self.class_defs_size)]:
            if n>MAX_TABLE_ITEMS: raise ValueError(f'DEX {name} table exceeds limit')
        _need(b,self.string_ids_off,self.string_ids_size*4); _need(b,self.type_ids_off,self.type_ids_size*4); _need(b,self.proto_ids_off,self.proto_ids_size*12); _need(b,self.method_ids_off,self.method_ids_size*8); _need(b,self.class_defs_off,self.class_defs_size*32)
        self.strings=[mutf8_at(b,u32(b,self.string_ids_off+i*4)) for i in range(self.string_ids_size)]
        self.types=[self.strings[u32(b,self.type_ids_off+i*4)] for i in range(self.type_ids_size)]
        self.protos=[]
        for i in range(self.proto_ids_size):
            o=self.proto_ids_off+i*12; ret=u32(b,o+4); po=u32(b,o+8); params=[]
            if ret>=len(self.types): raise ValueError('DEX proto return type out of range')
            if po:
                n=u32(b,po); _need(b,po+4,n*2); params=[self.types[u16(b,po+4+2*j)] for j in range(n)]
            self.protos.append((self.types[ret],params))
        self.methods=[]
        for i in range(self.method_ids_size):
            o=self.method_ids_off+i*8; ci=u16(b,o); pi=u16(b,o+2); ni=u32(b,o+4)
            if ci>=len(self.types) or pi>=len(self.protos) or ni>=len(self.strings): raise ValueError('DEX method id out of range')
            self.methods.append((self.types[ci],self.strings[ni],self.protos[pi]))
        self.code={}
        for i in range(self.class_defs_size):
            o=self.class_defs_off+i*32; cdo=u32(b,o+24)
            if not cdo: continue
            p=cdo; sf,p=uleb(b,p); inf,p=uleb(b,p); dm,p=uleb(b,p); vm,p=uleb(b,p)
            for n in (sf,inf):
                idx=0
                for _ in range(n): d,p=uleb(b,p); idx+=d; _,p=uleb(b,p)
            for n in (dm,vm):
                idx=0
                for _ in range(n):
                    d,p=uleb(b,p); idx+=d; _,p=uleb(b,p); co,p=uleb(b,p)
                    if idx>=self.method_ids_size: raise ValueError('Encoded method index out of range')
                    if co: _need(b,co,16); self.code[idx]=co

    def mstr(self,i):
        if i<0 or i>=len(self.methods): raise ValueError('Method index out of range')
        c,n,(r,p)=self.methods[i]; return f'{c}->{n}({"".join(p)}){r}'

    def refs(self,mid):
        b=self.b; co=self.code.get(mid,0)
        if not co: return []
        n=u32(b,co+12); p=co+16; end=p+n*2; _need(b,p,n*2); out=[]
        while p<end:
            cu=u16(b,p); op=cu&0xff; hi=cu>>8
            if op==0 and hi in (1,2,3):
                if hi==1: size=u16(b,p+2); w=4+size*2
                elif hi==2: size=u16(b,p+2); w=2+size*4
                else: ew=u16(b,p+2); size=u32(b,p+4); w=4+((ew*size+1)//2)
                if p+w*2>end: break
                p+=w*2; continue
            w=WIDTH.get(op,1)
            if p+w*2>end: break
            try:
                if op==0x1a:
                    idx=u16(b,p+2)
                    if idx<len(self.strings): out.append(('string',idx,self.strings[idx]))
                elif op==0x1b:
                    idx=u32(b,p+2)
                    if idx<len(self.strings): out.append(('string',idx,self.strings[idx]))
                elif 0x6e<=op<=0x72 or 0x74<=op<=0x78 or op in (0xfa,0xfb):
                    idx=u16(b,p+2)
                    if idx<len(self.methods): out.append(('invoke',idx,self.mstr(idx)))
            except (ValueError,struct.error): pass
            p+=w*2
        return out

    def xor_call_candidates(self,mid):
        b=self.b; co=self.code.get(mid,0)
        if not co: return []
        n=u32(b,co+12); base=co+16; end=base+n*2; _need(b,base,n*2); regs={}; out=[]; p=base
        while p<end:
            cu=u16(b,p); op=cu&0xff; hi=cu>>8
            if op==0 and hi in (1,2,3):
                try:
                    if hi==1: size=u16(b,p+2); w=4+size*2
                    elif hi==2: size=u16(b,p+2); w=2+size*4
                    else: ew=u16(b,p+2); size=u32(b,p+4); w=4+((ew*size+1)//2)
                except ValueError: break
                if p+w*2>end: break
                p+=w*2; continue
            w=WIDTH.get(op,1)
            if p+w*2>end: break
            try:
                if op in (0x01,0x07): A=hi&0xf; B=(hi>>4)&0xf; regs[A]=regs.get(B)
                elif op in (0x02,0x08): A=hi; B=u16(b,p+2); regs[A]=regs.get(B)
                elif op in (0x03,0x09): A=u16(b,p+2); B=u16(b,p+4); regs[A]=regs.get(B)
                elif op==0x12: A=hi&0xf; regs[A]=signed((hi>>4)&0xf,4)
                elif op==0x13: regs[hi]=signed(u16(b,p+2),16)
                elif op==0x14: regs[hi]=signed(u32(b,p+2),32)
                elif op==0x15: regs[hi]=signed(u16(b,p+2),16)<<16
                elif op==0x23:
                    A=hi&0xf; B=(hi>>4)&0xf; tidx=u16(b,p+2); ln=regs.get(B)
                    if tidx<len(self.types) and self.types[tidx]=='[B' and isinstance(ln,int) and 0<=ln<1_000_000: regs[A]=bytearray(ln)
                elif op==0x26:
                    A=hi; off=signed(u32(b,p+2),32); pp=p+off*2
                    ew=u16(b,pp+2); sz=u32(b,pp+4); total=ew*sz
                    if total<=1_000_000: _need(b,pp+8,total); regs[A]=bytearray(b[pp+8:pp+8+total]) if ew==1 else regs.get(A)
                elif 0x6e<=op<=0x72:
                    count=(cu>>12)&0xf; G=(cu>>8)&0xf; idx=u16(b,p+2); rr=u16(b,p+4)
                    if idx>=len(self.methods): raise ValueError('invoke method out of range')
                    r=[rr&0xf,(rr>>4)&0xf,(rr>>8)&0xf,(rr>>12)&0xf,G][:count]; vals=[regs.get(x) for x in r]; ms=self.mstr(idx)
                    if ms.endswith('([B[B)Ljava/lang/String;') and len(vals)>=2 and all(isinstance(v,(bytes,bytearray)) for v in vals[:2]): out.append((ms,bytes(vals[0]),bytes(vals[1])))
                elif 0x74<=op<=0x78:
                    count=hi; idx=u16(b,p+2); start=u16(b,p+4)
                    if idx>=len(self.methods) or count>256: raise ValueError('invoke/range invalid')
                    vals=[regs.get(x) for x in range(start,start+count)]; ms=self.mstr(idx)
                    if ms.endswith('([B[B)Ljava/lang/String;') and len(vals)>=2 and all(isinstance(v,(bytes,bytearray)) for v in vals[:2]): out.append((ms,bytes(vals[0]),bytes(vals[1])))
            except (ValueError,struct.error,OverflowError): pass
            p+=w*2
        return out

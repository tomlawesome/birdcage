// AC · Ribbons. Four silk ribbons in the canary colours; they settle into the dashboard's four traces.
const BG = (() => {
  let gl, prog, U = {}, W, H, D, t0 = 0, tFrozen = null;
  const P = { mix: 0, life: 1, tight: 0, out: 0, bg: 1 };
  const pulses = [];
  const VS = 'attribute vec2 a;void main(){gl_Position=vec4(a,0.,1.);}';
  const FS = `precision highp float;
uniform vec2 R;uniform float T,D,MIX,LIFE,TIGHT,OUT,BGA,SC,OX,OY,FX;uniform float PA[6];
const vec3 C0=vec3(.224,.529,.898),C1=vec3(.098,.62,.439),C2=vec3(.83,.55,.06),C3=vec3(.843,.416,.62);
float h(vec2 p){return fract(sin(dot(p,vec2(12.9898,78.233)))*43758.5453);}
vec4 rib(vec2 p,float i,vec3 c,float ty,vec4 acc,inout vec3 glow){
  float u=p.x/R.x;
  float per=mix(mix(.13,1.,smoothstep(.2,.95,u)),1.,MIX);
  float ph=i*1.7;
  float spread=mix(1.,.38,TIGHT);
  float wave=R.y*(.5+.40*pow(1.-smoothstep(.22,.8,u),1.3)+spread*(i-1.5)*.085*per)
    +R.y*per*(.20*sin(u*3.1+T*.21+ph)+.085*sin(u*7.3-T*.33+ph*2.3)+.03*sin(u*15.+T*.5+ph*4.))*mix(1.,.5,TIGHT);
  float yc=mix(wave,ty,MIX*MIX*(3.-2.*MIX));
  float th=u*(5.+i*.9)+T*(.27+.05*i)+ph*2.+TIGHT*u*9.;
  float pg=0.;
  for(int k=0;k<6;k++){float xp=FX+PA[k]*1100.*D;float q=(p.x-xp)/(90.*D);pg+=exp(-q*q)*step(0.,PA[k])*exp(-PA[k]*.9);}
  th+=pg*.9;
  float ct=cos(th);
  float hw=mix(R.y*.085*per*(.07+.93*abs(ct))*(1.+pg*.25),1.1*D,MIX);
  float dy=p.y-yc;float v=dy/hw;float av=abs(v);
  float aa=1.5*D/hw;
  float a=1.-smoothstep(1.-aa,1.,av);
  float front=step(0.,ct);
  float fib=.93+.07*sin(v*31.+i*3.)*sin(v*9.+u*30.);
  float sheen=.50+.50*cos(v*1.5);
  float spec=pow(max(0.,cos(th-.55-v*.5)),26.)*.62+pow(1.-av,3.)*.12;
  vec3 base=mix(c*.34+vec3(.0,.01,.04),c,front);
  vec3 col=base*(.30+.95*abs(ct))*sheen*fib+vec3(1.,.96,.9)*spec*(.35+.65*front)+c*pg*.3;
  float g=dot(col,vec3(.3,.5,.2));
  col=mix(vec3(g)*vec3(.62,.7,.9)*.55,col,LIFE);
  col=mix(col,c*1.25,MIX);
  float dim=mix(mix(.62,1.,smoothstep(.25,.6,u)),1.,MIX);
  col*=dim;
  float xm=mix(1.,step(OX+190.*SC,p.x)*step(p.x,OX+1368.*SC),smoothstep(.6,1.,MIX));
  a*=xm*(1.-OUT)*mix(.93,1.,MIX);
  glow+=c*exp(-abs(dy)/(hw*1.2+26.*D*per))*.085*mix(.25,1.,LIFE)*dim*xm*(1.-OUT)*(1.+pg);
  acc.rgb=mix(acc.rgb,col,a*(1.-acc.a*0.)); acc.a=max(acc.a,a);
  return acc;
}
void main(){
  vec2 p=vec2(gl_FragCoord.x,R.y-gl_FragCoord.y);vec2 uv=p/R;
  vec3 bg=vec3(.024,.031,.055);
  bg+=vec3(.03,.045,.09)*exp(-dot(uv-vec2(.72,.5),uv-vec2(.72,.5))*3.)*mix(.4,1.,LIFE);
  bg*=1.-.55*dot(uv-.5,uv-.5);
  vec4 acc=vec4(bg,0.);vec3 glow=vec3(0.);
  float t0y=OY+299.6*SC,t1=OY+311.8*SC,t2=OY+324.*SC,t3=OY+336.*SC;
  acc=rib(p,3.,C3,t3,acc,glow);acc=rib(p,1.,C1,t1,acc,glow);acc=rib(p,2.,C2,t2,acc,glow);acc=rib(p,0.,C0,t0y,acc,glow);
  vec3 col=acc.rgb+glow;
  col+=(h(gl_FragCoord.xy+T)-.5)*.022;
  float al=max(BGA,max(acc.a,min(1.,dot(glow,vec3(1.))*1.5)*(1.-OUT)));
  gl_FragColor=vec4(col,al);
}`;
  function sh(type, src) { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) console.error(gl.getShaderInfoLog(s)); return s; }
  function size() { D = Math.min(devicePixelRatio || 1, 2); W = innerWidth; H = innerHeight; const c = $('#bg'); c.width = W * D; c.height = H * D; gl.viewport(0, 0, c.width, c.height); }
  return {
    init() {
      const c = $('#bg'); gl = c.getContext('webgl', { antialias: false, alpha: true, premultipliedAlpha: false, preserveDrawingBuffer: true });
      prog = gl.createProgram(); gl.attachShader(prog, sh(gl.VERTEX_SHADER, VS)); gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, FS)); gl.linkProgram(prog); gl.useProgram(prog);
      gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer()); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
      const a = gl.getAttribLocation(prog, 'a'); gl.enableVertexAttribArray(a); gl.vertexAttribPointer(a, 2, gl.FLOAT, false, 0, 0);
      for (const n of ['R', 'T', 'D', 'MIX', 'LIFE', 'TIGHT', 'OUT', 'BGA', 'SC', 'OX', 'OY', 'FX', 'PA']) U[n] = gl.getUniformLocation(prog, n);
      size(); addEventListener('resize', size);
    },
    set(next, prev, instant) {
      const ms = (m) => (instant ? 0 : m);
      $('#shell').style.transition = instant ? 'none' : 'opacity 1400ms ease 900ms';
      $('#shell').style.opacity = next === 'in' ? 1 : 0;
      if (next === 'signin') { tween(P, 'mix', 0, ms(900)); tween(P, 'life', 1, ms(900)); tween(P, 'tight', 0, ms(900)); tween(P, 'out', 0, ms(300)); tween(P, 'bg', 1, ms(300)); }
      if (next === 'refused') { tween(P, 'life', .08, ms(500)); tween(P, 'tight', 0, ms(600)); tween(P, 'mix', 0, ms(600)); tween(P, 'out', 0, 0); tween(P, 'bg', 1, 0); }
      if (next === 'code') { tween(P, 'life', 1, ms(700)); tween(P, 'tight', 1, ms(1500)); tween(P, 'mix', 0, ms(600)); tween(P, 'out', 0, 0); tween(P, 'bg', 1, 0); if (!instant) pulses.push(performance.now() / 1000); }
      if (next === 'in') { tween(P, 'life', 1, ms(400)); tween(P, 'mix', 1, ms(2300)); tween(P, 'bg', 0, ms(1400), instant ? 0 : 900); tween(P, 'out', 1, ms(900), instant ? 0 : 2700); }
    },
    key() { if (state === 'refused') tween(P, 'life', 1, 600); pulses.push(performance.now() / 1000); while (pulses.length > 6) pulses.shift(); },
    poke(o) { tweens.clear(); if (o.pulses) { pulses.length = 0; const n = performance.now() / 1000; o.pulses.forEach((a) => pulses.push(n - a)); } if (o.t != null) tFrozen = o.t; Object.assign(P, o); },
    frame(t) {
      if (!t0) t0 = t;
      const s = Math.max(W / 1440, H / 900), ox = (W - 1440 * s) / 2, oy = (H - 900 * s) / 2;
      const now = performance.now() / 1000; const pa = new Float32Array(6).fill(-1);
      pulses.slice(-6).forEach((p, i) => { pa[i] = now - p; });
      const fr = $('.door').getBoundingClientRect().right;
      gl.uniform2f(U.R, W * D, H * D); gl.uniform1f(U.T, tFrozen != null ? tFrozen : STILL ? 14 : t - t0 + 14); gl.uniform1f(U.D, D);
      gl.uniform1f(U.MIX, P.mix); gl.uniform1f(U.LIFE, P.life); gl.uniform1f(U.TIGHT, P.tight); gl.uniform1f(U.OUT, P.out); gl.uniform1f(U.BGA, P.bg);
      gl.uniform1f(U.SC, s * D); gl.uniform1f(U.OX, ox * D); gl.uniform1f(U.OY, oy * D); gl.uniform1f(U.FX, fr * D); gl.uniform1fv(U.PA, pa);
      gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT); gl.drawArrays(gl.TRIANGLES, 0, 3);
    },
  };
})();

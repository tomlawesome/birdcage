// AB · Reeded glass. A wall of fluted glass with the four canaries' colours as light behind it;
// the form is on one flat smoked leaf that slides along the wall. Entering parts the wall like
// two sliding doors, and the dashboard is behind it.
const BG = (() => {
  const P = { leaf: 0, la: 1, life: 1, open: 0, surge: 0 };
  let gl, prog, U = {}, W, H, D, t0 = performance.now() / 1000;
  const VS = 'attribute vec2 a;void main(){gl_Position=vec4(a,0.,1.);}';
  const FS = `precision highp float;
uniform vec2 R;uniform float T,LX,LW,LA,LIFE,DPR,SURGE,OPEN,CX;
float hash(vec2 p){return fract(sin(dot(p,vec2(12.9898,78.233)))*43758.5453);}
vec3 blob(vec2 p,vec2 c,vec2 r,vec3 col,float b){vec2 rr=r*r+b*b;vec2 d=p-c;return col*exp(-d.x*d.x/rr.x-d.y*d.y/rr.y)*(r.x*r.y)/sqrt(rr.x*rr.y);}
vec3 lights(vec2 p,float b){
  float a=R.x/R.y,t=T*.06;vec3 c=vec3(.006,.010,.022);
  c+=blob(p,vec2(a*(.10+.04*sin(t*1.3)),.58+.10*cos(t)),vec2(.13,.30),vec3(.08,.30,.95),b);
  c+=blob(p,vec2(a*(.26+.05*cos(t*.8)),.22+.06*sin(t*1.2)),vec2(.10,.20),vec3(.20,.42,1.)*.7,b);
  c+=blob(p,vec2(a*(.43+.05*sin(t*.9+1.)),.70+.09*sin(t*1.1)),vec2(.10,.26),vec3(.03,.60,.40),b);
  c+=blob(p,vec2(a*(.52+.04*cos(t*1.1+2.)),.26+.07*cos(t*.9)),vec2(.07,.16),vec3(.10,.70,.55)*.6,b);
  c+=blob(p,vec2(a*(.68+.05*cos(t*1.2)),.44+.10*sin(t*.8+2.)),vec2(.11,.30),vec3(1.,.52,.04),b);
  c+=blob(p,vec2(a*(.78+.04*sin(t*.7+1.)),.84+.04*cos(t)),vec2(.09,.14),vec3(1.,.70,.30)*.7,b);
  c+=blob(p,vec2(a*(.91+.04*sin(t+3.)),.62+.08*cos(t*1.4)),vec2(.09,.26),vec3(.92,.28,.55),b);
  c+=blob(p,vec2(a*(.97+.03*cos(t*.6)),.20+.06*sin(t)),vec2(.08,.18),vec3(.70,.30,.80)*.6,b);
  c+=blob(p,vec2(a*(1.3*SURGE-.15),.5),vec2(.07,.9),vec3(1.,.86,.62)*sin(SURGE*3.1416)*1.3,b);
  c*=LIFE;return 1.-exp(-c*1.35);}
void main(){
  vec2 fc=gl_FragCoord.xy;float y=fc.y,w=24.*DPR;
  float side=fc.x<CX?-1.:1.;float x=fc.x-side*OPEN;
  float gap=side*(x-CX);
  if(gap<0.){float e=-gap,o=min(fc.x-(CX-OPEN),(CX+OPEN)-fc.x);gl_FragColor=vec4(0.,0.,0.,.62*exp(-o/(70.*DPR)));return;}
  float f=fract(x/w)-.5,k=-f*w;
  vec3 col=vec3(lights(vec2(x+k*10.4,y)/R.y,.02).r,lights(vec2(x+k*9.,y)/R.y,.02).g,lights(vec2(x+k*7.7,y)/R.y,.02).b);
  float lum=dot(col,vec3(.3,.5,.2));
  col*=1.-.46*smoothstep(.24,.5,abs(f));
  col*=1.-.10*(.5+.5*cos(f*6.283));
  col+=vec3(.62,.72,1.)*(.07+.55*lum)*(exp(-pow((f+.24)/.030,2.))*.5+exp(-pow((f-.37)/.016,2.))*.2);
  col+=vec3(.55,.66,1.)*.05*smoothstep(.35,0.,abs(x/R.x+.35*y/R.y-.78))*(.4+exp(-pow((f+.24)/.05,2.)));
  float d=max(LX-x,x-LX-LW);
  col*=1.-.6*LA*exp(-max(d,0.)/(50.*DPR));
  if(d<0.){
    vec3 lf=lights(vec2(x,y)/R.y,.34)*.26+vec3(.008,.011,.022);
    lf+=vec3(.5,.62,1.)*.030*smoothstep(.25,.95,1.-abs((x-LX)/LW-.10-.30*y/R.y));
    float e=min(x-LX,LX+LW-x);
    lf+=vec3(.78,.86,1.)*(.55*exp(-e/(.8*DPR))+.045*exp(-e/(12.*DPR)));
    col=mix(col,lf,LA);}
  col+=vec3(.8,.88,1.)*.7*exp(-gap/(.9*DPR))*step(.5,OPEN);
  float v=length((fc/R-.5)*vec2(1.,.9));col*=1.-.5*v*v;
  col+=(hash(fc+fract(T)*61.)-.5)*.028;
  gl_FragColor=vec4(col,1.);}`;
  function sh(type, src) { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) console.error(gl.getShaderInfoLog(s)); return s; }
  const LW = 500;
  const rest = () => Math.max(Math.round(W * .085 / 24) * 24, 96);
  const split = () => Math.round(W * .5 / 24) * 24;
  const far = () => split() + 72;
  function size() { D = Math.min(devicePixelRatio || 1, 2); W = innerWidth; H = innerHeight; const c = $('#bg'); c.width = W * D; c.height = H * D; gl.viewport(0, 0, c.width, c.height); }
  return {
    init() {
      const c = $('#bg'); gl = c.getContext('webgl', { antialias: false, alpha: true, premultipliedAlpha: false, preserveDrawingBuffer: true });
      prog = gl.createProgram(); gl.attachShader(prog, sh(gl.VERTEX_SHADER, VS)); gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, FS)); gl.linkProgram(prog); gl.useProgram(prog);
      gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer()); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
      const a = gl.getAttribLocation(prog, 'a'); gl.enableVertexAttribArray(a); gl.vertexAttribPointer(a, 2, gl.FLOAT, false, 0, 0);
      for (const n of ['R', 'T', 'LX', 'LW', 'LA', 'LIFE', 'DPR', 'SURGE', 'OPEN', 'CX']) U[n] = gl.getUniformLocation(prog, n);
      size(); addEventListener('resize', () => { size(); P.leaf = state === 'signin' || state === 'refused' ? rest() : far(); }); P.leaf = rest();
    },
    set(next, prev, instant) {
      const ms = instant ? 0 : 1;
      $('#shell').style.opacity = next === 'in' ? 1 : 0;
      if (next === 'signin') { tween(P, 'leaf', rest(), 1200 * ms); tween(P, 'life', 1, 900 * ms); tween(P, 'open', 0, 900 * ms); }
      if (next === 'refused') { P.leaf = rest(); P.open = 0; tween(P, 'life', .05, 240 * ms); tween(P, 'life', .30, 1500 * ms, 420 * ms); }
      if (next === 'code') { P.open = 0; tween(P, 'leaf', far(), 1400 * ms); tween(P, 'life', 1.3, 1200 * ms); P.surge = 0; tween(P, 'surge', 1, 1600 * ms, 0, (u) => u); }
      if (next === 'in') { P.leaf = far(); tween(P, 'life', 1.5, 500 * ms); tween(P, 'open', W * .5 + 30, 2200 * ms, 350 * ms); }
    },
    poke(o) { tweens.clear(); Object.assign(P, o); },
    frame(t) {
      $('.door').style.transform = `translateX(${P.leaf + (P.leaf + LW / 2 < split() ? -P.open : P.open)}px)`;
      gl.uniform2f(U.R, W * D, H * D); gl.uniform1f(U.T, STILL ? 3 : t - t0 + 3);
      gl.uniform1f(U.LX, P.leaf * D); gl.uniform1f(U.LW, LW * D); gl.uniform1f(U.LA, P.la);
      gl.uniform1f(U.LIFE, P.life); gl.uniform1f(U.DPR, D); gl.uniform1f(U.SURGE, P.surge); gl.uniform1f(U.OPEN, P.open * D); gl.uniform1f(U.CX, split() * D);
      gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT); gl.drawArrays(gl.TRIANGLES, 0, 3);
    },
  };
})();

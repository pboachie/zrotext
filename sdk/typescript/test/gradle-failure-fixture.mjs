// SPDX-License-Identifier: AGPL-3.0-only
// Fixed public Gradle indicators, not a root-cause assertion or a log collector.
const markers=[
  ['dependency-verification','Dependency verification failed for configuration '],
  ['dependency-verification','Dependency verification failed for artifact '],
  ['dependency-resolution','Could not resolve all files for configuration '],
  ['dependency-resolution','Could not resolve all artifacts for configuration '],
  ['java-tls','PKIX path building failed'],
  ['java-tls','javax.net.ssl.SSLHandshakeException'],
  ['gradle-daemon','Gradle build daemon disappeared unexpectedly'],
  ['gradle-daemon','Unable to start the daemon process.'],
].map(([category,text])=>{
  const bytes=Buffer.from(text,'ascii'),fallback=new Array(bytes.length).fill(0);
  for(let at=1,matched=0;at<bytes.length;at++){
    while(matched&&bytes[at]!==bytes[matched])matched=fallback[matched-1];
    if(bytes[at]===bytes[matched])matched++;
    fallback[at]=matched;
  }
  return {category,bytes,fallback};
});
export function createGradleFailureSignals(){
  // Keep only integer positions and fixed category flags, never child bytes,
  // decoded stderr, paths, environment, credentials or signing material.
  const positions={stdout:markers.map(()=>0),stderr:markers.map(()=>0)},seen=new Set();let invalid=false;
  return {
    feed(stream,chunk){
      if(invalid)return;
      if((stream!=='stdout'&&stream!=='stderr')||!Buffer.isBuffer(chunk)){invalid=true;seen.clear();return;}
      for(let index=0;index<markers.length;index++){
        const {category,bytes,fallback}=markers[index];if(seen.has(category))continue;
        let matched=positions[stream][index];
        for(const byte of chunk){
          while(matched&&byte!==bytes[matched])matched=fallback[matched-1];
          if(byte===bytes[matched])matched++;
          if(matched===bytes.length){seen.add(category);matched=0;break;}
        }
        positions[stream][index]=matched;
      }
    },
    snapshot(){
      const observed=[...new Set(markers.map(({category})=>category))].filter(category=>seen.has(category));
      return Object.freeze(invalid||!observed.length?['unknown']:observed);
    },
  };
}

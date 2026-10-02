export function responseLike(data,status=200){
  return {ok:status>=200&&status<300,status,json:async()=>data};
}

export async function pollActiveRequest(requestFn,path,opts={},config={}){
  const maxAttempts=Number(config.maxAttempts??120);
  const intervalMs=Number(config.intervalMs??1000);
  const sleep=config.sleep??(ms=>new Promise(resolve=>setTimeout(resolve,ms)));

  const initial=await requestFn(path,opts);
  if(!initial.ok)return initial;
  const body=await initial.json();
  if(!body?.job_id)return responseLike(body,initial.status);

  for(let attempt=0;attempt<maxAttempts;attempt++){
    const poll=await requestFn("/api/v1/operations/jobs/"+encodeURIComponent(body.job_id));
    if(!poll.ok)return poll;
    const job=await poll.json();
    if(job.status==="succeeded")return responseLike(job.result??{},200);
    if(job.status==="failed"||job.status==="cancelled"){
      return responseLike({detail:job.error||job.status},409);
    }
    if(attempt<maxAttempts-1)await sleep(intervalMs);
  }
  return responseLike({detail:"operation timeout"},504);
}

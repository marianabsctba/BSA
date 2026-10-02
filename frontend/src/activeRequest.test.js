import { describe, expect, it, vi } from "vitest";
import { pollActiveRequest, responseLike } from "./activeRequest.js";

describe("pollActiveRequest",()=>{
  it("returns immediate non-queued responses unchanged",async()=>{
    const requestFn=vi.fn().mockResolvedValue(responseLike({ok:true},200));
    const response=await pollActiveRequest(requestFn,"/x",{},{});
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ok:true});
    expect(requestFn).toHaveBeenCalledTimes(1);
  });

  it("polls queued operations until success",async()=>{
    const requestFn=vi.fn()
      .mockResolvedValueOnce(responseLike({job_id:"job-1",status:"queued"},202))
      .mockResolvedValueOnce(responseLike({status:"running"},200))
      .mockResolvedValueOnce(responseLike({status:"succeeded",result:{assets:4}},200));

    const response=await pollActiveRequest(
      requestFn,
      "/api/v1/discovery",
      {method:"POST"},
      {maxAttempts:3,intervalMs:0,sleep:async()=>{}},
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({assets:4});
    expect(requestFn).toHaveBeenNthCalledWith(
      2,
      "/api/v1/operations/jobs/job-1",
    );
  });

  it("surfaces failed queued operations",async()=>{
    const requestFn=vi.fn()
      .mockResolvedValueOnce(responseLike({job_id:"job-2",status:"queued"},202))
      .mockResolvedValueOnce(responseLike({status:"failed",error:"engine failed"},200));

    const response=await pollActiveRequest(
      requestFn,
      "/active",
      {method:"POST"},
      {maxAttempts:2,intervalMs:0,sleep:async()=>{}},
    );

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({detail:"engine failed"});
  });

  it("returns timeout after bounded polling",async()=>{
    const requestFn=vi.fn()
      .mockResolvedValueOnce(responseLike({job_id:"job-3",status:"queued"},202))
      .mockResolvedValue(responseLike({status:"running"},200));

    const response=await pollActiveRequest(
      requestFn,
      "/active",
      {method:"POST"},
      {maxAttempts:2,intervalMs:0,sleep:async()=>{}},
    );

    expect(response.status).toBe(504);
    expect(await response.json()).toEqual({detail:"operation timeout"});
  });
});

// SPDX-License-Identifier: AGPL-3.0-only
const labels=Object.freeze(['original_current','original_read','original_page','context_metadata','context_content','routine_current','original_admit','call_current','produced']);
export class RequestHistogram {
  #rows=new Map(labels.map(label=>[label,{count:0,sum:0,max:0}]));
  record(label,elapsed){
    const row=this.#rows.get(label);
    if(!row||!Number.isFinite(elapsed)||elapsed<0||row.count>=64)return;
    const ms=Math.min(60000,Math.floor(elapsed));
    row.count++;row.sum=Math.min(60000,row.sum+ms);row.max=Math.max(row.max,ms);
  }
  failureLines(){const fields=labels.flatMap(label=>{const row=this.#rows.get(label);return row.count?[`${label}=${row.count},${row.sum},${row.max}`]:[];});return fields.length?`original routine requests ${fields.join(' ')}\n`:'';}
}

"""Record actual successful training microbatches, without storing prompt content."""
import hashlib,json
from datetime import datetime,timezone,timedelta
META='_soc_prefix_ids'
def prefix_identity(source,index):
    value={'record_id':source.get('id'),'source':source.get('source'),'assistant_message_index':index,'record_sha256':hashlib.sha256(json.dumps(source,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
    value['prefix_id']=hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
    return value

def recorded_trainer(parent,path):
    class RecordedTrainer(parent):
        def compute_loss(self,model,inputs,*args,**kwargs):
            inputs.pop(META,None)
            return super().compute_loss(model,inputs,*args,**kwargs)
        def prediction_step(self,model,inputs,*args,**kwargs):
            inputs.pop(META,None)
            return super().prediction_step(model,inputs,*args,**kwargs)
        def training_step(self,model,inputs,*args,**kwargs):
            identities=inputs.pop(META,None)
            if not identities:raise ValueError('Missing actual training prefix identity')
            result=super().training_step(model,inputs,*args,**kwargs)
            # This records successful microbatch forward/backward, not a claim
            # that the subsequent optimizer update or run completed.
            row={'at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(),'optimizer_step_before':self.state.global_step,'successful_forward_backward':True,'prefixes':identities}
            with path.open('a') as stream:stream.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+'\n');stream.flush()
            return result
    return RecordedTrainer

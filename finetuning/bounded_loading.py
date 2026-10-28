"""Release each CPU checkpoint mapping after its tensor is copied to the GPU.

Transformers 5.4 normally retains all safetensors slices until loading finishes.
On Thor, device copies can turn those private file mappings into resident anonymous
memory. Keep metadata only, and reopen a mapping for each synchronous tensor read.
The library installation and checkpoint bytes are never modified.
"""
from contextlib import contextmanager
import os


class ReopeningSlice:
    def __init__(self, opener, filename, key, shape, dtype):
        self.opener, self.filename, self.key = opener, filename, key
        self.shape, self.dtype = shape, dtype

    def get_shape(self): return list(self.shape)
    def get_dtype(self): return self.dtype

    def __getitem__(self, item):
        with self.opener(self.filename, framework='pt', device='cpu') as handle:
            return handle.get_slice(self.key)[item]


class ReopeningFile:
    def __init__(self, opener, filename, framework, device='cpu'):
        if framework != 'pt' or str(device) != 'cpu':
            raise ValueError('Bounded checkpoint loader supports CPU PyTorch reads only')
        self.opener, self.filename = opener, filename
        with opener(filename, framework='pt', device='cpu') as handle:
            self._metadata = handle.metadata()
            self.slices = {key: ReopeningSlice(opener, filename, key,
                handle.get_slice(key).get_shape(), handle.get_slice(key).get_dtype()) for key in handle.keys()}

    def keys(self): return list(self.slices)
    def metadata(self): return self._metadata
    def get_slice(self, key): return self.slices[key]
    def get_tensor(self, key): return self.get_slice(key)[...]
    def __enter__(self): return self
    def __exit__(self, *args): return False


@contextmanager
def checkpoint_loading(config, diagnostics=None):
    if config.get('model_kind') != 'qwen3_5_moe':
        yield
        return
    import transformers
    import transformers.modeling_utils as modeling
    if transformers.__version__ != '5.4.0':
        raise RuntimeError('Revalidate bounded loading before changing Transformers 5.4.0')
    original = modeling.safe_open
    original_warmup = modeling.caching_allocator_warmup if diagnostics is not None else None
    if diagnostics is not None:
        def measured_warmup(*args, **kwargs):
            diagnostics('allocator_warmup_start')
            try:
                result = original_warmup(*args, **kwargs)
            except Exception:
                diagnostics('allocator_warmup_failed')
                raise
            diagnostics('allocator_warmup_completed')
            return result
        modeling.caching_allocator_warmup = measured_warmup
    previous = os.environ.get('HF_DEACTIVATE_ASYNC_LOAD')
    os.environ['HF_DEACTIVATE_ASYNC_LOAD'] = '1'
    modeling.safe_open = lambda filename, framework, device='cpu': ReopeningFile(original, filename, framework, device)
    try:
        yield
    finally:
        modeling.safe_open = original
        if original_warmup is not None:modeling.caching_allocator_warmup = original_warmup
        if previous is None: os.environ.pop('HF_DEACTIVATE_ASYNC_LOAD', None)
        else: os.environ['HF_DEACTIVATE_ASYNC_LOAD'] = previous

#ifndef SRC_ALLOCS_H_
#define SRC_ALLOCS_H_

extern "C" {
typedef bool _Bool;
#include <liballocs.h>
}
#include <ffi.h>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::Boolean;
using v8::Context;
using v8::EscapableHandleScope;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
using v8::HeapStatistics;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Locker;
using v8::Message;
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::Persistent;
using v8::PropertyCallbackInfo;
using v8::String;
using v8::TryCatch;
using v8::Uint32;
using v8::V8;
using v8::Value;
using v8::kExternalUnsignedIntArray;

extern Persistent<ObjectTemplate, v8::CopyablePersistentTraits<ObjectTemplate> > allocs_struct_template;
extern Persistent<ObjectTemplate, v8::CopyablePersistentTraits<ObjectTemplate> > allocs_array_template;
extern Persistent<ObjectTemplate, v8::CopyablePersistentTraits<ObjectTemplate> > allocs_base_template;
extern Persistent<FunctionTemplate, v8::CopyablePersistentTraits<FunctionTemplate> > allocs_function_template;

/* HACK: unbelievably, this is what the v8 devs recommend
 * for dereferencing a persistent handle. See: 
 * https://groups.google.com/d/msg/v8-users/6kSAbnUb-rQ/QPMMfqssx5AJ
 */
#define PERSISTENT_DEREFABLE_AS(T, p)   (*reinterpret_cast<Local< T >*>(&(p)))
#define LOCAL_DEREFABLE_AS(T, p)   (*reinterpret_cast<Local< T >*>(&(p)))

void LinkMapGetter(Local<String> property,
                   const PropertyCallbackInfo<Value>& info);

void LinkMapSetter(Local<String> property,
                          Local<Value> value,
                          const PropertyCallbackInfo<Value>& info);

void LinkMapQuery(Local<String> property,
                         const PropertyCallbackInfo<Integer>& info);

void LinkMapDeleter(Local<String> property,
                    const PropertyCallbackInfo<Boolean>& info);

void LinkMapEnumerator(const PropertyCallbackInfo<Array>& info);

void AllocsStructGetter(Local<String> property,
                        const PropertyCallbackInfo<Value>& info);

void AllocsStructSetter(Local<String> property,
                        Local<Value> value,
                        const PropertyCallbackInfo<Value>& info);

void AllocsStructQuery(Local<String> property,
                       const PropertyCallbackInfo<Integer>& info);

void AllocsStructDeleter(Local<String> property,
                         const PropertyCallbackInfo<Boolean>& info);

void AllocsStructEnumerator(const PropertyCallbackInfo<Array>& info);

void AllocsArrayGetter(uint32_t index,
                       const PropertyCallbackInfo<Value>& info);

void AllocsArraySetter(uint32_t index,
                       Local<Value> value,
                       const PropertyCallbackInfo<Value>& info);

void AllocsArrayQuery(uint32_t index,
                      const PropertyCallbackInfo<Integer>& info);

void AllocsArrayDeleter(uint32_t index,
                        const PropertyCallbackInfo<Boolean>& info);

void AllocsArrayEnumerator(const PropertyCallbackInfo<Array>& info);

void AllocsBaseGetter(uint32_t index,
                       const PropertyCallbackInfo<Value>& info);

void AllocsBaseSetter(uint32_t index,
                       Local<Value> value,
                       const PropertyCallbackInfo<Value>& info);

void AllocsBaseQuery(uint32_t index,
                      const PropertyCallbackInfo<Integer>& info);

void AllocsBaseDeleter(uint32_t index,
                        const PropertyCallbackInfo<Boolean>& info);

void AllocsBaseEnumerator(const PropertyCallbackInfo<Array>& info);
void AllocsBasePrinter(const FunctionCallbackInfo<Value>& args);

void AllocsFunctionPrinter(const FunctionCallbackInfo<Value>& args);

void AllocsFunctionCaller(const FunctionCallbackInfo<Value>& info);

Local<Value> v8_get_outermost_object(Environment *env, void *ptr, 
    struct uniqtype **out_innermost);
struct uniqtype *v8_get_outermost_uniqtype(void *ptr);
Local<Value> v8_get_object(Environment *env, void *ptr, 
    struct uniqtype *outermost, 
    struct uniqtype **out_innermost);
Local<Value> v8_get_object_with_type(Environment *env, void *ptr, 
    struct uniqtype *t);
Local<Value> v8_get_object_typeless(Environment *env, void *ptr);
Local<Value> v8_get_primitive(Environment *env, void *ptr, struct uniqtype *prim_t);
_Bool v8_put_primitive(Environment *env, void *ptr, struct uniqtype *prim_t, Local<Value> value_to_put);
Local<Value> v8_get_indexed(Environment *env, void *ptr, int ind, struct uniqtype *element_outermost);
Local<Value> v8_get_named(Environment *env, void *ptr, const char *n, struct uniqtype *element_outermost);
Local<Value> v8_set_indexed(Environment *env, void *ptr, int ind, 
    struct uniqtype *element_outermost, void *val);
Local<Value> v8_set_named(Environment *env, void *ptr, const char *n, 
    struct uniqtype *element_outermost, void *val);
ffi_type *ffi_type_for_uniqtype(struct uniqtype *t);
intptr_t v8_make_uniqtype_instance(Environment *env, Local<Value> v, struct uniqtype *t);
Local<Value> v8_make_value(Environment *env, void *p_val_raw, struct uniqtype *t);
} // end namespace node

#endif

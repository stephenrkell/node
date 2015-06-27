/* Code for interfacing with liballocs. */

#include "v8.h"  // NOLINT(build/include_order)
#include "node.h"
#include "env.h"
#include "env-inl.h"
#include "allocs.h"

extern "C" {
typedef bool _Bool;
#include <liballocs.h>
}
#include <link.h> /* link map stuff */
#include <cassert>
#include <cstring>

using node::Environment;
using v8::Undefined;
using v8::Local;
using v8::String;
using v8::Array;
using v8::Integer;
using v8::Boolean;
using v8::Object;
using v8::Value;
using v8::NumberObject;
using v8::StringObject;
using v8::ObjectTemplate;
using v8::Persistent;
using v8::HandleScope;
using v8::External;
using v8::PropertyCallbackInfo;
using v8::FunctionCallbackInfo;

#define MANGLE_POINTER_INTERNAL(ptr) ((void*) ( ((uintptr_t)(ptr)) << 1u ))
#define DEMANGLE_POINTER_INTERNAL(m) ((void*) ( ((uintptr_t)(m)) >> 1u ))
// HACK HACK HACK HACK HACK!
#define IS_NATIVE_OBJECT(v) ((v)->IsObject() && (v)->InternalFieldCount() == 2)

namespace node
{
Persistent<ObjectTemplate, v8::CopyablePersistentTraits<ObjectTemplate> > allocs_struct_template;
Persistent<ObjectTemplate, v8::CopyablePersistentTraits<ObjectTemplate> > allocs_array_template;
Persistent<ObjectTemplate, v8::CopyablePersistentTraits<ObjectTemplate> > allocs_base_template;
Persistent<FunctionTemplate, v8::CopyablePersistentTraits<FunctionTemplate> > allocs_function_template;

void LinkMapGetter(Local<String> property,
                          const PropertyCallbackInfo<Value>& info) {
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  HandleScope scope(env->isolate());
#ifdef __POSIX__
  String::Utf8Value key(property);
  dlerror();
  void* addr = dlsym(RTLD_DEFAULT, *key);
  /* If we were asked for something that doesn't exist, we can return now. */
  if (!addr)
  {
    return;
  }
  /* What does addr point to? If it's a primitive or a char* with a sane 
   * target, we intervene. */
  struct uniqtype *innermost = NULL;
  Local<Value> obj = v8_get_object(env, addr, NULL, &innermost);
  if (!obj->IsUndefined() /*&& innermost != NULL*/)
  {
    /* We succeeded. This object will be an instance of the
     * Struct or Array or Function templates. We should really
     * intervene in the case where the target is a char array,
     * but we don't do this for now. FIXME.
     */
     info.GetReturnValue().Set(obj);
     return;
  }
//   else if (innermost == NULL)
//   {
//     /* It's actually a primitive. So we read a value and JavaScriptify it. 
//      * OH, but what if we want a mutable integer, say? That needs to be an object too. */
//     Local<Value> val = v8_get_primitive(env, addr, innermost);
//     info.GetReturnValue().Set(val);
//     return;
//   }

#else  // _WIN32
#error "Unimplemented"
#endif
  // Not found.  Fetch from prototype.
}


void LinkMapSetter(Local<String> property,
                   Local<Value> value,
                   const PropertyCallbackInfo<Value>& info) {
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  HandleScope scope(env->isolate());
#ifdef __POSIX__
  String::Utf8Value key(property);
  String::Utf8Value val(value);

  // can't dynamically add to link map at present

#else  // _WIN32
#error "Unimplemented"
#endif
}


void LinkMapQuery(Local<String> property,
                  const PropertyCallbackInfo<Integer>& info) {
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  HandleScope scope(env->isolate());
#ifdef __POSIX__
  String::Utf8Value key(property);
  dlerror();
  if (dlsym(RTLD_DEFAULT, *key)) {
    info.GetReturnValue().Set(static_cast<int32_t>(v8::ReadOnly) |
           static_cast<int32_t>(v8::DontDelete));
  }
#else  // _WIN32
#error "Unimplemented"
#endif
  // Not found
}


void LinkMapDeleter(Local<String> property,
                    const PropertyCallbackInfo<Boolean>& info) {
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  HandleScope scope(env->isolate());
#ifdef __POSIX__
  // String::Utf8Value key(property);
  /*if (!getenv(*key))*/
  // unsetenv(*key); // can't check return value, it's void on some platforms
  // return True();
#else
#error "Unimplemented"
#endif
  info.GetReturnValue().Set(false); // always fail
}

int syms_count_callback(const ElfW(Sym) *sym, char* loadAddress, char *strtab, void *data)
{
    ++*(unsigned long *)data;
    return 0;
}

struct add_sym_arg
{
    Local<Array> allSyms;
    int *p_i;
    Environment *env;
};
int syms_add_callback(const ElfW(Sym) *sym, char* loadAddress, char *strtab, void *data)
{
    struct add_sym_arg *p_add_sym_arg = static_cast<struct add_sym_arg *>(data);
    Local<Array> allSyms = p_add_sym_arg->allSyms;
    // (*p_allSyms)->Set((*p_add_sym_arg->p_i)++, External::New(loadAddress + sym->st_value));
    // we set the symbol *name*, not the contents!
    char *symname = strtab + sym->st_name;
    size_t symname_len = strlen(symname);
    // fprintf(stderr, "Saw symbol %s\n", symname);
    
    allSyms->Set((*p_add_sym_arg->p_i), String::NewFromUtf8(p_add_sym_arg->env->isolate(),
        symname, String::kNormalString, symname_len));
    
    ++(*p_add_sym_arg->p_i);
    return 0;
}

int iterate_global_dynamic_syms(
    const ElfW(Sym) *syms, unsigned long nsyms, char *loadAddress, char *strtab,
    int (*cb)(const ElfW(Sym) *, char */*loadAddress*/, char */*strtab*/, void */*data*/), void *arg)
{
    int ret = 0;
    for (unsigned long i = 0; i != nsyms; ++i)
    {
        if (
            (ELF64_ST_TYPE(syms[i].st_info) == STT_FUNC
            || ELF64_ST_TYPE(syms[i].st_info) == STT_OBJECT)
            && ELF64_ST_BIND(syms[i].st_info) == STB_GLOBAL
            && syms[i].st_shndx != SHN_UNDEF
            && syms[i].st_shndx != SHN_ABS)
        {
            ret = cb(syms + i, loadAddress, strtab, arg);
            if (ret != 0) break;
        }
    }
    return ret;
}

struct iterate_syms_arg
{
    int (*cb)(const ElfW(Sym) *, char*, char*, void *);
    void *arg;
};

int visit_one_obj_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
    struct iterate_syms_arg *syms_cb = static_cast<struct iterate_syms_arg *>(data);
    /* Get the symtab and then call our iteration function on it. */
    const ElfW(Phdr) *p_phdr = info->dlpi_phdr;
    while (p_phdr->p_type != PT_DYNAMIC && p_phdr->p_type != PT_NULL) ++p_phdr;
    
    if (p_phdr->p_type == PT_DYNAMIC // skip kernel-side p_dyns (vdso)
        && static_cast<intptr_t>(p_phdr->p_vaddr) > 0)
    {
        const ElfW(Dyn) *p_dyn = reinterpret_cast<const ElfW(Dyn)*>(
         (char *) info->dlpi_addr + p_phdr->p_vaddr);
        const ElfW(Sym) *p_dynsym = 0;
        char *p_dynstr = 0;
        char *p_hash = 0;
        while (p_dyn->d_tag != DT_NULL)
        {
            switch (p_dyn->d_tag)
            {
                case DT_SYMTAB:
                    p_dynsym = reinterpret_cast<const ElfW(Sym)*>(/*(char*) info->dlpi_addr
                        + */p_dyn->d_un.d_ptr);
                    break;
                case DT_STRTAB:
                    p_dynstr = (char*) /*info->dlpi_addr + */p_dyn->d_un.d_ptr;
                    break;
                case DT_HASH:
                    p_hash = (char*) /*info->dlpi_addr + */p_dyn->d_un.d_ptr;
                    break;
                default: break;
            }
            ++p_dyn;
        }
        if (!p_dynsym || !p_dynstr) return 0;
        assert((char*) p_dynstr > (char*) p_dynsym);
        assert(((char*) p_dynstr - (char*) p_dynsym) % sizeof (ElfW(Sym)) == 0);
        
        iterate_global_dynamic_syms(
            p_dynsym,
            /* FIXME: use nchain instead of this hack! */
            ((char*) p_dynstr - (char*) p_dynsym) / sizeof (ElfW(Sym)),
            (char*) info->dlpi_addr,
            p_dynstr,
            syms_cb->cb,
            syms_cb->arg
        );
        
        return 0; // keep going
    }
    else
    {
        // we didn't find a DYNAMIC! oh well. keep going
        return 0;
    }
}

void LinkMapEnumerator(const PropertyCallbackInfo<Array>& info) {
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  HandleScope scope(env->isolate());
#ifdef __POSIX__
  /* We enumerate all the global dynamically-linked symbols 
   * across all files in the link map. */
  int size = 0;
  // while (environ[size]) size++;
  struct iterate_syms_arg syms_arg = { &syms_count_callback, &size };
  dl_iterate_phdr(&visit_one_obj_phdr, &syms_arg);

  Local<Array> allSyms = Array::New(env->isolate(), size);
  int count = 0;
  struct add_sym_arg add_arg = { allSyms, &count, env };
  struct iterate_syms_arg next_syms_arg = { &syms_add_callback, &add_arg };

  dl_iterate_phdr(&visit_one_obj_phdr, &next_syms_arg);
  assert(count == size);
  
#else  // _WIN32
#error "Unimplemented"
#endif
  info.GetReturnValue().Set(allSyms);
}


void AllocsStructGetter(Local<String> property,
                        const PropertyCallbackInfo<Value>& info) {
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  HandleScope scope(env->isolate());

  struct uniqtype *outermost = static_cast<struct uniqtype*>(
    info.This()->GetAlignedPointerFromInternalField(1));
  void *obj = DEMANGLE_POINTER_INTERNAL(info.This()->GetAlignedPointerFromInternalField(0));

  if (!outermost) return;
  Dl_info i = dladdr_with_cache(outermost);
  if (i.dli_sname)
  {
    char *names_name = strdup(i.dli_sname);
    String::Utf8Value key(property);
    
    names_name = (char*) realloc(names_name, strlen(names_name) + sizeof "_subobj_names" + 1 /* HACK: necessary? */);
    strcat(names_name, "_subobj_names");
    void *handle = dlopen(i.dli_fname, RTLD_NOW | RTLD_NOLOAD);
    if (handle)
    {
      char **names_name_array = static_cast<char **>(dlsym(handle, names_name));
      if (names_name_array)
      {
        /* Linear-search for a field named `key`. */
        for (char **p_name = names_name_array; *p_name; ++p_name)
        {
          const char *name = *p_name;
          unsigned index = p_name - names_name_array;
          if (0 == strcmp(name, *key))
          {
            Local<Value> subobj = v8_get_object(env, (char*) obj + outermost->contained[index].offset, 
              outermost->contained[index].ptr, NULL);
            info.GetReturnValue().Set(subobj);
            break; // success!
          }
          else {} // name doesn't match
        } // end for
      }
      else
      {
        /* We have no names array, so bail */
      }
    }
    else // handle is null
    {
      assert(false); // this shouldn't happen
    }
    
    dlclose(handle); // decrement refcount
    free(names_name);
  } // else no dli_sname -- shouldn't happen
  
  // Not found.  Fetch from prototype.
}
void AllocsStructSetter(Local<String> property,
                        Local<Value> value,
                        const PropertyCallbackInfo<Value>& info) {
}
void AllocsStructQuery(Local<String> property,
                       const PropertyCallbackInfo<Integer>& info) {
}
void AllocsStructDeleter(Local<String> property,
                         const PropertyCallbackInfo<Boolean>& info) {
}
void AllocsStructEnumerator(const PropertyCallbackInfo<Array>& info) {
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  struct uniqtype *outermost = static_cast<struct uniqtype*>(
    info.This()->GetAlignedPointerFromInternalField(1));
  /* To get the subobject names, we use dladdr to get the uniqtype's 
   * canonical symbol name, then use dlsym to look for _subobj_names. */
  if (!outermost) return;
  int size = outermost->nmemb;
  Dl_info i = dladdr_with_cache(outermost);
  if (i.dli_sname)
  {
    char *names_name = strdup(i.dli_sname);
    names_name = (char*) realloc(names_name, strlen(names_name) + sizeof "_subobj_names" + 1 /* HACK: necessary? */);
    strcat(names_name, "_subobj_names");
    void *handle = dlopen(i.dli_fname, RTLD_NOW | RTLD_NOLOAD);
    assert(handle);
    void *found = dlsym(handle, names_name);
    Local<Array> allMembs = Array::New(env->isolate(), size);
    if (found)
    {
      for (int i = 0; i < size; ++i)
      {
        const char *str = ((char **) found)[i];
        allMembs->Set(i, String::NewFromUtf8(env->isolate(), str, String::kNormalString, strlen(str)));
      }
      info.GetReturnValue().Set(allMembs);
    }
    else
    {
      for (unsigned i = 0; i < (unsigned) size; ++i)
      {
        char buf[1 + (sizeof (unsigned) * 3) + 1]; /* '_' + log10 uint_max + '\0' */
        snprintf(buf, sizeof buf, "_%u", i);
        allMembs->Set(i, String::NewFromUtf8(env->isolate(), buf, String::kNormalString, strlen(buf)));
        info.GetReturnValue().Set(allMembs);
      }
    }
    free(names_name);
    dlclose(handle); // decrement refcount
  }

}

void AllocsArrayGetter(uint32_t index,
                       const PropertyCallbackInfo<Value>& info) {
}
void AllocsArraySetter(uint32_t index,
                       Local<Value> value,
                       const PropertyCallbackInfo<Value>& info) {
}
void AllocsArrayQuery(uint32_t index,
                      const PropertyCallbackInfo<Integer>& info) {
}
void AllocsArrayDeleter(uint32_t index,
                        const PropertyCallbackInfo<Boolean>& info) {
}
void AllocsArrayEnumerator(const PropertyCallbackInfo<Array>& info) {
}
void AllocsBaseGetter(uint32_t index,
                       const PropertyCallbackInfo<Value>& info) {}

void AllocsBaseSetter(uint32_t index,
                       Local<Value> value,
                       const PropertyCallbackInfo<Value>& info) {}

void AllocsBaseQuery(uint32_t index,
                      const PropertyCallbackInfo<Integer>& info) {}

void AllocsBaseDeleter(uint32_t index,
                        const PropertyCallbackInfo<Boolean>& info) {}

void AllocsBaseEnumerator(const PropertyCallbackInfo<Array>& info) {}

void AllocsBasePrinter(const FunctionCallbackInfo<Value>& info)
{
  Environment* env = Environment::GetCurrent(info.GetIsolate());
  void *obj = DEMANGLE_POINTER_INTERNAL(info.This()->GetAlignedPointerFromInternalField(0));
  assert(info.This()->IsObject());
  Local<Object> native = info.This()->ToObject();
  assert(IS_NATIVE_OBJECT(native));
  struct uniqtype *t = static_cast<struct uniqtype *>(native->GetAlignedPointerFromInternalField(1));
  assert(t);
  /* Make a V8 primitive from the value, and run "inspect" on that. 
   * But how? It's not an object. Answer: call into node's util.inspect.
   * This is defined in JavaScript! How can we link to it? 
   * I don't yet know, but since inspectors are allowed to return
   * another Object, just try returning the value we got. */
  Local<Value> prim = v8_make_value(env, obj, t);
  info.GetReturnValue().Set(prim);
}

void AllocsFunctionPrinter(const FunctionCallbackInfo<Value>& args) {
    void *callee = DEMANGLE_POINTER_INTERNAL(args.This()/*.As<Object>()*/
      ->GetAlignedPointerFromInternalField(0));
    struct uniqtype *callee_uniqtype = v8_get_outermost_uniqtype(callee);
    args.GetReturnValue().Set(
      String::Concat(FIXED_ONE_BYTE_STRING(args.GetIsolate(), "native function, uniqtype "),
        FIXED_ONE_BYTE_STRING(args.GetIsolate(), callee_uniqtype ? callee_uniqtype->name : "(none)")));
}

void AllocsFunctionCaller(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  
  /* What do we do with our arguments? */
  
  /* In general: get what the uniqtype says they are, and 
   * coerce them to it. 
   * 
   * numbers {float, int, etc.} -- okay
   * immediate arrays           -- okay, copy in from the object's indexed properties
   * immediate structs          -- okay, copy in from the object's named properties
   * pointer to char            -- bit ambiguous, but try to make a string and pass that
   * pointer to non-char:       -- HMM
   *     -- if the function wants a pointer-to-int, what do we give it? 
   *             -- give it a pointer to a temporary buffer we create, holding an int
   *             -- do pre- and post-copy from/to whatever object we were passed
   *             -- this approach means that saving a pointer is always a bad thing for a native function to do
   *             -- WHAT does node-ffi or ref do?
   
   WOULD it be sane to protect all memory except the stack during the call, to trap writes and 
           ensure that they don't save the pointer? Seems like it would work, but it's slow
           
           BETTER is to sweep this memory as if it were a GC root, hence allowing 
           the pointer to be saved.
  
   NOTE that our temporary object is in C++-land, so no need to worry about it moving.
  
   * 
   * This is a simple API mapping! Want it to be user-customisable!
   */

  unsigned call_arg_count = args.Length();
  assert(args.This()->InternalFieldCount() >= 2);
  /* Note that the callee function, from our point of view, is the receiver 
   * of the call-as-function, i.e. the "This". The Callee() is just the Function, 
   * not its Instance. No, I don't really understand why all the indirection is necessary. */
  void *callee = DEMANGLE_POINTER_INTERNAL(args.This()/*.As<Object>()*/->GetAlignedPointerFromInternalField(0));
  struct uniqtype *callee_uniqtype = v8_get_outermost_uniqtype(callee);
  if (!callee_uniqtype) callee_uniqtype = &__liballocs_uniqtype_of_typeless_functions;
  assert(UNIQTYPE_IS_SUBPROGRAM(callee_uniqtype));
  
  ffi_type **ffi_type_buf = (ffi_type **) alloca(call_arg_count * sizeof (ffi_type *));
  // do we need temporaries? not yet
  void **ffi_arg_buf = (void **) alloca(call_arg_count * sizeof (void *));
  void **ffi_arg_values = (void **) alloca(call_arg_count * sizeof (void *));
  /* FIXME: non-wordsize args */

  unsigned uniqtype_arg_count = UNIQTYPE_SUBPROGRAM_ARG_COUNT(callee_uniqtype);
  for (unsigned i_arg = 0; i_arg < call_arg_count; ++i_arg)
  {
    struct uniqtype *arg_type = (i_arg < uniqtype_arg_count)
     ? callee_uniqtype->contained[i_arg + 1u].ptr
     : NULL;
    ffi_type_buf[i_arg] = ffi_type_for_uniqtype(arg_type);
    fprintf(stderr, "Trying to get a value of uniqtype %s for argument %u\n", 
      !arg_type ? "(no uniqtype)" : arg_type->name ? arg_type->name : "(no name)", i_arg);
    fflush(stderr);
    ffi_arg_values[i_arg] = (void*) v8_make_uniqtype_instance(env, args[i_arg], arg_type);
    ffi_arg_buf[i_arg] = &ffi_arg_values[i_arg];
  }

  ffi_arg result;
  struct uniqtype *result_uniqtype = callee_uniqtype->contained[0].ptr;
  ffi_type *result_type = ffi_type_for_uniqtype(result_uniqtype);

  ffi_status status;
  ffi_cif cif;
  
  // Prepare the ffi_cif structure
  if ((status = ffi_prep_cif(&cif, FFI_DEFAULT_ABI,
          call_arg_count, result_type, ffi_type_buf)) != FFI_OK)
  {
      // Handle the ffi_status error.
      assert(false);
  }

  // Invoke the function.
  //fprintf(stderr, "FFI-calling function at %p with arguments [", callee);
  for (unsigned i = 0; i < call_arg_count; i++)
  {
      //if (i != 0) fprintf(stderr, ", ");
      //fprintf(stderr, "<in ffi_arg buf at %p, pointing to %p, word value %p>\n",
      //  &ffi_arg_buf[i], ffi_arg_buf[i], (void*) *(unw_word_t*)ffi_arg_buf[i]);
  }
  //fprintf(stderr, "]\n");
  //fflush(stderr);

  // do it
  ffi_call(&cif, FFI_FN(callee), &result, ffi_arg_buf);
  
  /* Handle return value. If we're an "untyped" function, we drop the 
   * type for the call to v8_make_value, so that it can guess int/pointer
   * based on the value. */
  if (callee_uniqtype == &__liballocs_uniqtype_of_typeless_functions)
  {
    args.GetReturnValue().Set(
      v8_make_value(env, &result, NULL)
    );
  }
  else
  {
    assert(false);
    args.GetReturnValue().Set(
      v8_make_value(env, &result, result_uniqtype)
    );
  }

}

Local<Value> v8_get_outermost_object(Environment *env, void *ptr, 
    struct uniqtype **out_innermost)
{
  return v8_get_object(env, ptr, NULL, out_innermost);
}

struct uniqtype *v8_get_outermost_uniqtype(void *ptr)
{
  /* If the object that we point to is a primitive, we will
   * fail but return a lower bound. The caller can then 
   * fall back at creating a primitive, using the lower bound
   * to decode it. */

  memory_kind k;
  const void *alloc_start;
  unsigned long alloc_size;
  struct uniqtype *alloc_uniqtype = (struct uniqtype *)0;
  const void *alloc_site;

  __liballocs_ensure_init();
  struct liballocs_err *err = __liballocs_get_alloc_info(ptr, 
      &k,
      &alloc_start,
      &alloc_size,
      &alloc_uniqtype,
      &alloc_site);

  /* If we didn't abort, it means we now know what's on the end of the pointer. */
  if (err) return NULL;

  signed target_offset_within_uniqtype = ((char*) ptr - (char*) alloc_start) % 
    ((alloc_uniqtype && alloc_uniqtype->pos_maxoff != 0) ? alloc_uniqtype->pos_maxoff : 1);

  // traverse and/or descend subobjects until we get to an instance of anything
  struct uniqtype *last_attempted = NULL;
  _Bool success = __liballocs_find_matching_subobject(target_offset_within_uniqtype,
      alloc_uniqtype, NULL, &last_attempted, NULL, NULL);
  
  return success ? (last_attempted ? last_attempted : alloc_uniqtype) : NULL;
}

Local<Value> v8_get_object(Environment *env, void *ptr, 
    struct uniqtype *outermost, 
    struct uniqtype **out_innermost)
{

  struct uniqtype *found = v8_get_outermost_uniqtype(ptr);
  // If we succeeded, we either have an object or a primitive. 
  // -- we're undefined if there was a bound and we fail
  if (!found) return /* outermost ? Undefined(env->isolate()).As<Value>() :*/ v8_get_object_typeless(env, ptr); // Undefined(env->isolate());

  // traverse and/or descend subobjects until we get to an instance of the outermost
  _Bool success = __liballocs_find_matching_subobject(0,
      found, outermost, NULL, NULL, NULL);

  // If we succeeded, we either have an object or a primitive. 
  // -- we're undefined if there was a bound and we fail
  if (!success) return /*outermost ? Undefined(env->isolate()).As<Value>() : */ v8_get_object_typeless(env, ptr); // Undefined(env->isolate());

  return v8_get_object_with_type(env, ptr, outermost ? outermost : found);
}

Local<Value> v8_get_object_typeless(Environment *env, void *ptr)
{
  /* This means we were asked for something that we have no type info for. 
   * If it's in a text segment, we treat is as a function from VA to unsigned long.
   * Otherwise we treat it as an error. */
  // fprintf(stderr, "Warning: object at %p has no uniqtype info", addr);
  struct mapping_info *dl_info = __liballocs_mapping_lookup(ptr);
  if (dl_info && dl_info->f.kind == STATIC && dl_info->f.x)
  {
    //fprintf(stderr, ", treating as a variadic-to-word function\n");

    /* Return an object that uses our function template. How do we do that? */
    return v8_get_object_with_type(env, ptr, &__liballocs_uniqtype_of_typeless_functions);
  }
  return Object::New(env->isolate());
}

Local<Value> v8_get_object_template_for_type(Isolate *i, struct uniqtype *t)
{
    if (UNIQTYPE_IS_ARRAY(t))// && !UNIQTYPE_IS_POINTER_TYPE(t))
    {
      /* We can create a new object using the array template. */
      Local<ObjectTemplate> array_l = Local<ObjectTemplate>::New(i, allocs_array_template);
      return LOCAL_DEREFABLE_AS(Object, array_l);
    }
    //else if (t->is_array && UNIQTYPE_IS_POINTER_TYPE(UNIQTYPE_POINTEE_TYPE(t)))
    //{
    //  /* Ptr points to a pointer. FIXME */
    //  return Undefined(env->isolate());
    //}
    else if (UNIQTYPE_HAS_SUBOBJECTS(t))
    {
      /* We can create a new object using the struct template. */
      Local<ObjectTemplate> struct_l = Local<ObjectTemplate>::New(i, allocs_struct_template);
      return LOCAL_DEREFABLE_AS(Object, struct_l);
    }
    else if (UNIQTYPE_IS_SUBPROGRAM(t))
    {
      /* We can create a new object using the function template. */
      Local<FunctionTemplate> function_l = Local<FunctionTemplate>::New(i, allocs_function_template);
      Local<Function> fun = function_l->GetFunction();
      return LOCAL_DEREFABLE_AS(Object, fun);
    }
    else if (UNIQTYPE_IS_BASE_OR_ENUM_TYPE(t))
    {
      /* Create a mutable base object. */
      Local<ObjectTemplate> base_l = Local<ObjectTemplate>::New(i, allocs_base_template);
      return LOCAL_DEREFABLE_AS(Object, base_l);
     }
    else
    {
      // we fail, but passing the upper bound (also lower bound, since it's primitive)
      // of what's on the end of the pointer
      // if (out_innermost) *out_innermost = t;
      return Undefined(i);
    }
    
    // end of case split
    assert(false);

}

Local<Value> v8_get_object_with_type(Environment *env, void *ptr, 
    struct uniqtype *t)
{
  /* Handling of primitives:
   * 
   * We used to say that
   * 
   * "If the object that we point to is a primitive, we will
   * fail but return a lower bound. The caller can then 
   * fall back at creating a primitive, using the lower bound
   * to decode it."
   * 
   * but that doesn't handle mutation of primitives.
   * Instead we want to say:
   * 
   * mutable primitives are objects that "behave" like built-in number objects.
   *
   */
  assert(t);
    /* previously we did: 
       
       Local<Value> v = External::New(env->isolate(), val);
       info.GetReturnValue().Set(v);
       
       BUT what we really want to do is:
       
       - see if it's an object; if so, do the above; 
       
       - if it's a primitive or char*, we do something else.
     */
    
    /* What would we like to return instead of an External? 
     * Suppose the value is:
     *   1. a plain (mutable) int. 
     *      We'd like the LinkMapSetter to allow mutating this 
     *      and the LinkMapGetter to give us a nice JS number.  
     *   2. a struct containing a (mutable) int.
     *      We'd like the getter to return an object like our External
     *      *except* being an instance of a template that uses 
     *      libcrunch.
     *      
     */
    
    Local<Value> tmpl = v8_get_object_template_for_type(env->isolate(), t);
    Local<Object> obj;
    if (tmpl->IsUndefined()) return tmpl;
    
    if (tmpl->IsFunction())
    {
      obj = LOCAL_DEREFABLE_AS(Function, tmpl)->NewInstance();
    }
    else
    {
      obj = LOCAL_DEREFABLE_AS(ObjectTemplate, tmpl)->NewInstance();
    }
    /* Set its internal pointer field to the address of the array. */
    obj->SetAlignedPointerInInternalField(0, MANGLE_POINTER_INTERNAL(ptr));
    /* Set another internal pointer field to the upper bound. */
    obj->SetAlignedPointerInInternalField(1, t);
    return obj;
    
}
ffi_type *ffi_type_for_uniqtype(struct uniqtype *t)
{
  /* use something word-sized if t is null */
  if (!t) return &ffi_type_pointer;
  
  if (t == &__uniqtype__int) return &ffi_type_sint;
  if (t == &__uniqtype__unsigned_int) return &ffi_type_uint;
  if (t == &__uniqtype__long_int) return &ffi_type_slong;
  if (t == &__uniqtype__unsigned_long_int) return &ffi_type_ulong;
  if (t == &__uniqtype__short_int) return &ffi_type_sshort;
  if (t == &__uniqtype__short_unsigned_int) return &ffi_type_ushort;
  if (t == &__uniqtype__float) return &ffi_type_float;
  if (t == &__uniqtype__double) return &ffi_type_double;
  if (UNIQTYPE_IS_POINTER_TYPE(t)) return &ffi_type_pointer;
  
  assert(false);
}

Local<Value> v8_make_value(Environment *env, void *p_val_raw, struct uniqtype *t)
{
  ffi_arg *p_val = static_cast<ffi_arg *>(p_val_raw);
  if (!t)
  {
    /* guesswork! */
    if ((long) *p_val < 4194304 /* FIXME: const somewhere */)
    {
      /* it's not a pointer, so it must be an integer */
      return Number::New(env->isolate(), (double) (long) *p_val);
    }
    else
    {
      /* It might be a pointer, but does it point to a mapped page? */
      memory_kind k  = __liballocs_get_memory_kind((void *) *p_val);
      if (k == UNKNOWN) /* HACK: "slow path" API should do this for us. */
      {
        __liballocs_add_missing_maps();
        k  = __liballocs_get_memory_kind((void *) *p_val);
      }
      if (k != UNKNOWN && k != UNUSABLE)
      {
        /* It could be a pointer, so it is a pointer. 
         * HACK, FIXME, etc: we use the outermost uniqtype for now... */
        return v8_get_object(env, (void*) *p_val, NULL, NULL);
      }
      else
      {
        /* Pretend it's an integer. */
        return Number::New(env->isolate(), (double) (long) *p_val);
      }
    }
  }
  
  assert(t);
  /* t is the actual immediate type of *p_val. This should be easy. 
   * FIXME: this is architecture-specific because of long long etc. (and maybe endianness?) */
  if (t == &__uniqtype__int)                return Number::New(env->isolate(), (double) (int) *p_val);
  if (t == &__uniqtype__unsigned_long_int)  return Number::New(env->isolate(), (double) (unsigned long) *p_val);
  if (t == &__uniqtype__long_int)           return Number::New(env->isolate(), (double) (long) *p_val);
  if (t == &__uniqtype__unsigned_int)       return Number::New(env->isolate(), (double) (unsigned) *p_val);
  if (t == &__uniqtype__short_int)          return Number::New(env->isolate(), (double) (short) *p_val);
  if (t == &__uniqtype__short_unsigned_int) return Number::New(env->isolate(), (double) (unsigned short) *p_val);
  if (t == &__uniqtype__signed_char)        return Number::New(env->isolate(), (double) (char) *p_val);
  if (t == &__uniqtype__unsigned_char)      return Number::New(env->isolate(), (double) (unsigned char) *p_val);
  if (t == &__uniqtype__float)              return Number::New(env->isolate(), (double) *(float*) *p_val);
  if (t == &__uniqtype__double)             return Number::New(env->isolate(),*(double  *) p_val);
  else if (UNIQTYPE_IS_BASE_OR_ENUM_TYPE(t))
  {
    /* Use the size field to interpret it as a signed integer. */
    switch (t->pos_maxoff)
    {
      case 8:
        return Number::New(env->isolate(), (double) (long) *p_val);
      case 4:
        return Number::New(env->isolate(), (double) (int) *p_val);
      case 2:
        return Number::New(env->isolate(), (double) (short) *p_val);
      case 1:
        return Number::New(env->isolate(), (double) (signed char) *p_val);
      default:
        assert(false);
    }
  }
  else if (UNIQTYPE_IS_POINTER_TYPE(t))
  {
    /* FIXME: strings */
    return v8_get_object(env, (void*) *p_val, UNIQTYPE_POINTEE_TYPE(t), NULL);
  }
  assert(false); // structs, arrays, ...
}

void externalize_v8_heap_object(Environment *env, Local<Object> v, struct uniqtype *t)
{
  bool success = ExternalizeObject(v, t);
  /* The first internal field is set as the object address. We need to mangle it. */ 
  void *ptr = DEMANGLE_POINTER_INTERNAL(v->ToObject()->GetAlignedPointerFromInternalField(0));
  /* Set its internal pointer field to the address of the array. */
  v->SetAlignedPointerInInternalField(0, MANGLE_POINTER_INTERNAL(ptr));
  /* Set another internal pointer field to the upper bound. */
  v->SetAlignedPointerInInternalField(1, t);
}

intptr_t v8_make_uniqtype_instance(Environment *env, Local<Value> v, struct uniqtype *t)
{
  struct AllocsExternalStringResource : v8::String::ExternalAsciiStringResource
  {
    char *data_;
    size_t length_;

    /* CARE! */
    virtual void Dispose() 
    {
      if (data_) free(data_);
      delete this;
    }

    const char* data() const { return data_; }
    /** The number of ASCII characters in the string.*/
    virtual size_t length() const { return length_; }

    AllocsExternalStringResource(const String::Utf8Value& v)
     : ExternalAsciiStringResource(), data_(strdup(*v)), length_(strlen(data_)) {}
  };
  
  fprintf(stderr, "Handling V8 object whose toString says: %s\n", *v8::String::Utf8Value(v));
  fflush(stderr);
  if (v->IsObject()) {
    fprintf(stderr, "V8 object printer says: ");
    v8::PrintObject(v->ToObject());
  } else fprintf(stderr, "(not a V8 object)\n");
  fflush(stderr);
  /* We have various recipes for turning V8 values into native. 
   * Some of them work only for particular uniqtypes. */
#define GUARD(g) do { if (!(g)) goto ill_matched; } while (0)
  if (v->IsNull())
  {
    GUARD(!t || UNIQTYPE_IS_POINTER_TYPE(t));
    return 0;
  }
  else if (v->IsNumber() && (!t || UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(t)))
  {
    return (intptr_t) (long) v->ToNumber()->Value();
  }
  else if (v->IsNumberObject() && (!t || UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(t)))
  {
    return (intptr_t) (long) v->ToObject().As<NumberObject>()->NumberValue();
  }
  else if (v->IsNumber() && (UNIQTYPE_IS_BASE_OR_ENUM_TYPE(t) && !UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(t)))
  {
    double double_val = v->ToNumber()->Value();
    float float_val = (float) double_val;
    switch (t->pos_maxoff)
    {
      case 4: return *(intptr_t*) &float_val;
      case 8: return *(intptr_t*) &double_val;
      default:
        assert(false);
    }
  }
  else if (v->IsNumberObject() && (UNIQTYPE_IS_BASE_OR_ENUM_TYPE(t) && !UNIQTYPE_IS_2S_COMPL_INTEGER_TYPE(t)))
  {
    double double_val = v->ToObject().As<NumberObject>()->NumberValue();
    float float_val = (float) double_val;
    switch (t->pos_maxoff)
    {
      case 4: return *(intptr_t*) &float_val;
      case 8: return *(intptr_t*) &double_val;
      default:
        assert(false);
    }
  }
  else if (v->IsString())
  {
    GUARD(!t || UNIQTYPE_IS_POINTER_TYPE(t));
    /* We want a pointer to its raw chars. Also we want to keep this pointer
     * alive longer than just this function, so String::Utf8Value is not a goer. 
     * Instead, we try to make it external. */
    if (v->ToString()->IsExternal()) return (intptr_t) v->ToString()->GetExternalStringResource()->data();
    else
    {
      String::Utf8Value data(v->ToString());
      /* HACK: need to keep this data alive somehow... */
      AllocsExternalStringResource *p_res = new AllocsExternalStringResource(data);

      bool success = v->ToString()->MakeExternal(p_res);
      assert(success);

      return (intptr_t) p_res->data();
    }
  }
  else if (v->IsStringObject())
  {
    GUARD(!t || UNIQTYPE_IS_POINTER_TYPE(t));
    assert(false);
//     if (v->ToObject().As<StringObject>()->IsExternal())
//     {
//      return (intptr_t) v->ToObject().As<StringObject>()->GetExternalStringResource()->data();
//     }
//     else
//     {
//       String::Utf8Value data(v->ToString());
//       /* HACK: need to keep this data alive somehow... */
//       AllocsExternalStringResource *p_res = new AllocsExternalStringResource(data);
// 
//       bool success = v->ToObject().As<StringObject>()->MakeExternal(p_res);
//       assert(success);
// 
//       return (intptr_t) p_res->data();
//     }
  }
  else if (v->IsArray() && t && UNIQTYPE_IS_POINTER_TYPE(t))
  {
    /* We want to externalise the array and pass a pointer to it. */
    externalize_v8_heap_object(env, v->ToObject(), UNIQTYPE_POINTEE_TYPE(t));
    return (intptr_t) DEMANGLE_POINTER_INTERNAL(v->ToObject()->GetAlignedPointerFromInternalField(0));
  }
  /* what if v is an allocs object? */
  else if (v->IsObject() && IS_NATIVE_OBJECT(v->ToObject()))
  {
    /* FIXME: account for depth */
    return (intptr_t) DEMANGLE_POINTER_INTERNAL(v->ToObject()->GetAlignedPointerFromInternalField(0));
  }

  if (t && UNIQTYPE_IS_POINTER_TYPE(t))
  {
    /* We expect to have a JS object. 
       If the JS code got hold of it through us, 
       it will be an instance of one of our templates, 
       and will have a hidden field whose contents include the pointer we want.
     */
    
    
    /* If it's some other JS object, then we ought to
       
       - transform the JS object (and its reachables, up to t)
         so that it is laid out as t dictates;
         fix it so, and fix all these objects' addresses (until we have moving GC for C);
         pass its address.
      
       BUT we don't have that working yet. So instead, we assume that 
       a transient copy is okay. We try to deep-copy the JS object
       into the form demanded by the uniqtype.
     */
  }
  /* If we got here, we don't know how to handle this.
   * It might mean we're missing some uniqtypes information. */
  assert(false);
ill_matched:
  assert(false);
}

Local<Value> v8_get_primitive(Environment *env, void *ptr, struct uniqtype *prim_t)
{
    if (prim_t == &__uniqtype__int)
    {
      /* We're being asked to read an int. */
      return Integer::New(env->isolate(), *static_cast<int *>(ptr));
    } else return Undefined(env->isolate());
    //else if (prim_t == __uniqtype__
}

_Bool v8_put_primitive(Environment *env, void *ptr, struct uniqtype *prim_t, Local<Value> value_to_put)
{
  assert(false);
  return false;
}

Local<Value> v8_get_indexed(Environment *env, void *ptr, int ind, struct uniqtype *element_outermost)
{
  assert(false);
  return Undefined(env->isolate());
}

Local<Value> v8_get_named(Environment *env, void *ptr, const char *n, struct uniqtype *element_outermost)
{
  assert(false);
  return Undefined(env->isolate());
}

Local<Value> v8_set_indexed(Environment *env, void *ptr, int ind, 
    struct uniqtype *element_outermost, void *val)
{
    /* If we're setting a pointer and it's a JS object, 
     * we could create a persistent handle. When do we
     * destroy this handle? There's a clear risk of memory
     * leaks here. But we could look at the pointer we're overwriting to 
     * guess whether it's to a V8-heap object, and if so, 
     * manually destruct it (as a PersistentHandle) somehow. That doesn't handle
     * the case of random C code manipulating the same pointer field,
     * but that might be an unusual pattern. */
  assert(false);
  return Undefined(env->isolate());
}

Local<Value> v8_set_named(Environment *env, void *ptr, const char *n, 
    struct uniqtype *element_outermost, void *val)
{
  assert(false);
  return Undefined(env->isolate());
}

} // end namespace node

#ifndef MEMORY_UNIQUE_PTR_H
#define MEMORY_UNIQUE_PTR_H

namespace memory {
  template<typename T>
  class unique_ptr {
    public:
      // Constructor.
      unique_ptr() = default;
      unique_ptr(T* p);

      // Destructor.
      ~unique_ptr();

      // Reset.
      void reset(T* p = nullptr);

      // Release ownership.
      T* release();

      // Assigment operator.
      unique_ptr& operator=(T* p);

      // Dereference the stored pointer.
      T& operator*() const;

      // Return the stored pointer.
      T* operator->() const;

      // Return the stored pointer.
      T* get() const;

      // Return true if the stored pointer is not null.
      operator bool() const;

    private:
      T* _M_ptr = nullptr;

      // Disable copy constructor and assignment operator.
      unique_ptr(const unique_ptr&) = delete;
      unique_ptr& operator=(const unique_ptr&) = delete;
  };

  template<typename T>
  inline unique_ptr<T>::unique_ptr(T* p)
    : _M_ptr(p)
  {
  }

  template<typename T>
  inline unique_ptr<T>::~unique_ptr()
  {
    reset();
  }

  template<typename T>
  inline void unique_ptr<T>::reset(T* p)
  {
    if (_M_ptr) {
      delete _M_ptr;
    }

    _M_ptr = p;
  }

  template<typename T>
  inline T* unique_ptr<T>::release()
  {
    T* p = _M_ptr;
    _M_ptr = nullptr;

    return p;
  }

  template<typename T>
  inline unique_ptr<T>& unique_ptr<T>::operator=(T* p)
  {
    if (p != _M_ptr) {
      reset(p);
    }

    return *this;
  }

  template<typename T>
  inline T& unique_ptr<T>::operator*() const
  {
    return *_M_ptr;
  }

  template<typename T>
  inline T* unique_ptr<T>::operator->() const
  {
    return get();
  }

  template<typename T>
  inline T* unique_ptr<T>::get() const
  {
    return _M_ptr;
  }

  template<typename T>
  inline unique_ptr<T>::operator bool() const
  {
    return (_M_ptr != nullptr);
  }
}

#endif // MEMORY_UNIQUE_PTR_H

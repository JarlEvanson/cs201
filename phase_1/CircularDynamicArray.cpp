#include <cassert>
#include <climits>
#include <stddef.h>

template<typename T>
void swap_ptr(T* a, T* b) {
    T tmp = *a;
    *a = *b;
    *b = tmp;
}

size_t to_size_t(int num) {
    static_assert(sizeof(int) < sizeof(size_t));

    assert(num >= 0);

    return (size_t) num;
}

int to_int(size_t num) {
    assert(num <= (size_t) INT_MAX);

    return (int) num;
}

size_t wrap_underlying(size_t index, size_t buffer_size) {
    assert(index <= buffer_size || index == (0 - 1) && buffer_size != 0);

    if(index == buffer_size) {
        return 0;
    } else if(index == (size_t) ((size_t) 0 - (size_t) 1)) {
        return buffer_size - 1;
    }

    return index;
}

template<typename T>
class CircularDynamicArray {
private:
    T* base;
    size_t buffer_size;
    size_t size;

    size_t start;
    size_t end;

    T nonsense;

    T* get(size_t index);
    void grow();
    void shrink();
    size_t partition(size_t low, size_t high, size_t pivot_index);
public:
    CircularDynamicArray();
    CircularDynamicArray(int size);
    CircularDynamicArray(CircularDynamicArray& other);
    CircularDynamicArray& operator=(CircularDynamicArray& other);
    ~CircularDynamicArray();

    T& operator[](int i);

    void addEnd(T element);
    void addFront(T element);

    void delEnd();
    void delFront();

    void clear();

    T QSelect(int k);
    void Sort();
    int linearSearch(T element);
    int binSearch(T element);

    int length();
    int capacity();
};

template<typename T>
CircularDynamicArray<T>::CircularDynamicArray() {
    this->base = new T[2];
    this->buffer_size = 2;
    this->size = 0;

    this->start = 0;
    this->end = 0;
}

template<typename T>
CircularDynamicArray<T>::CircularDynamicArray(int input_size) {
    size_t size = to_size_t(input_size);

    this->base = new T[size];
    this->buffer_size = size;
    this->size = size;

    this->start = 0;
    this->end = 0;
}

template<typename T> 
CircularDynamicArray<T>::CircularDynamicArray(CircularDynamicArray& other) {
    this->base = new T[other.buffer_size];
    this->buffer_size = other.buffer_size;
    this->size = other.size;

    this->start = 0;
    this->end = other.size % other.buffer_size;

    for(size_t i = 0; i < this->size; i++) {
        this->base[i] = *other.get(i);
    }
}

template<typename T> 
CircularDynamicArray<T>& CircularDynamicArray<T>::operator=(CircularDynamicArray& other) {
    if(this == &other) 
        return *this;

    delete[] this->base; 

    this->base = new T[other.buffer_size];
    this->buffer_size = other.buffer_size;
    this->size = other.size;

    this->start = 0;
    this->end = other.size % other.buffer_size;

    for(size_t i = 0; i < this->size; i++) {
        this->base[i] = *other.get(i);
    }

    return *this;
}

template<typename T>
CircularDynamicArray<T>::~CircularDynamicArray() {
    delete[] this->base;

    this->base = nullptr;
    this->buffer_size = 0;
    this->size = 0;

    this->start = 0;
    this->end = 0;
}

template<typename T>
T& CircularDynamicArray<T>::operator[](int i) {
    if(i < 0 || i >= (int) this->size) {
        std::cout << "Index out of bounds: Programming error" << endl;
        return this->nonsense;
    }

    return *this->get(to_size_t(i));
}

template<typename T>
T* CircularDynamicArray<T>::get(size_t index) {
    assert(index < this->size);

    size_t underlying_index = this->start;
    size_t elements_before_wrap = this->buffer_size - this->start;

    if(index >= elements_before_wrap) {
        index -= elements_before_wrap;
        underlying_index = 0;
    }

    return &this->base[underlying_index + index];
}

template<typename T>
void CircularDynamicArray<T>::grow() {
    size_t new_buffer_size = this->buffer_size * 2;
    if(this->buffer_size == 0) {
        new_buffer_size = 2;
    } 
    
    assert(this->buffer_size == new_buffer_size / 2);
        
    T* new_ptr = new T[new_buffer_size];
    size_t old_index = this->start;

    for(size_t i = 0; i < this->size; i++) {
        new_ptr[i] = this->base[old_index];
        
        old_index += 1;
        if(old_index == this->buffer_size) {
            old_index = 0;
        }
    }

    delete[] this->base;
    this->base = new_ptr;
    this->buffer_size = new_buffer_size;
    this->start = 0;
    this->end = this->size;
}

template<typename T>
void CircularDynamicArray<T>::addFront(T element) {
    if(this->size == this->buffer_size) {
        this->grow();
    }

    size_t new_start = wrap_underlying(this->start - 1, this->buffer_size);
    
    this->start = new_start;
    this->base[this->start] = element;

    this->size += 1;
}

template<typename T>
void CircularDynamicArray<T>::addEnd(T element) {
    if(this->size == this->buffer_size) {
        this->grow();
    }

    size_t new_end = wrap_underlying(this->end + 1, this->buffer_size);
    
    this->base[this->end] = element;

    this->end = new_end;
    this->size += 1;
}

template<typename T>
void CircularDynamicArray<T>::shrink() {
    size_t new_buffer_size = this->buffer_size / 2;

    T* new_ptr = new T[new_buffer_size];
    size_t old_index = this->start;

    for(size_t i = 0; i < this->size; i++) {
        new_ptr[i] = this->base[old_index];

        old_index += 1;
        if(old_index == this->buffer_size) {
            old_index = 0;
        }
    }

    delete[] this->base;
    this->base = new_ptr;
    this->buffer_size = new_buffer_size;
    this->start = 0;
    this->end = this->size;
}

template<typename T>
void CircularDynamicArray<T>::delFront() {
    if(this->size == 0) {
        return;
    }

    size_t new_front = wrap_underlying(this->start + 1, this->buffer_size);

    this->start = new_front;
    this->size -= 1;

    if(this->size * 4 <= this->capacity() && this->size * 4 >= this->size) {
        this->shrink();
    }
}

template<typename T>
void CircularDynamicArray<T>::delEnd() {
    if(this->size == 0) {
        return;
    }

    size_t new_end = wrap_underlying(this->end - 1, this->buffer_size);

    this->end = new_end;
    this->size -= 1;

    if(this->size * 4 <= this->capacity() && this->size * 4 >= this->size) {
        this->shrink();
    }
}

template<typename T>
void CircularDynamicArray<T>::clear() {
    delete[] this->base;
    this->base = new T[2];
    this->buffer_size = 2;
    this->size = 0;

    this->start = 0;
    this->end = 0;
}

template<typename T> 
size_t CircularDynamicArray<T>::partition(
    size_t low, 
    size_t high, 
    size_t pivot_index
) {
    T pivot = *this->get(pivot_index);

    swap_ptr(this->get(pivot_index), this->get(high));
    size_t store_index = low;

     for(size_t index = low; index < high; index++) {
        T value = *this->get(index);
        if(value < pivot) {
            swap_ptr(this->get(index), this->get(store_index));
            store_index += 1;
        }
    }

    swap_ptr(this->get(high), this->get(store_index));
    return store_index;
}

template<typename T>
T CircularDynamicArray<T>::QSelect(int input_k) {
    if(this->size == 0) {
        return this->nonsense;
    }

    size_t k = to_size_t(input_k - 1);

    size_t low = 0;
    size_t high = this->size - 1;

    while(true) {
        if(low == high) {
            return *this->get(low);
        }

        size_t pivot_index = std::rand() % (high - low) + low;
        pivot_index = this->partition(low, high, pivot_index);

        if(k == pivot_index) {
            return *this->get(k);
        } else if(k < pivot_index) {
            high = pivot_index - 1;
        } else {
            low = pivot_index + 1;
        }
    }
}

template<typename T>
void CircularDynamicArray<T>::Sort() {
    if(this->size == 0) {
        return;
    }

    T* storage = new T[this->size];
    size_t output = 0;

    T* src = storage;
    size_t block_start;
    size_t left;
    size_t right;
    size_t i;
    size_t j;
    size_t end;
    size_t remaining;

    for(block_start = 0; block_start < (this->size / 2) * 2; block_start += 2, output += 2) {
        storage[output] = std::min(*this->get(block_start), *this->get(block_start + 1));
        storage[output + 1] = std::max(*this->get(block_start), *this->get(block_start + 1));
    }
    if(block_start != this->size) {
        storage[output] = *this->get(block_start);
    }

    src = storage;
    storage = this->base;

    for(size_t width = 2; width < this->size; width *= 2) {
        for(block_start = 0; block_start < this->size; block_start += 2 * width) {
            left = block_start;
            right = std::min(block_start + width, this->size);
            end = std::min(block_start + 2 * width, this->size);

            i = left;
            j = right;

            for(output = left; output < end; output++) {
                if(i < right && (j >= end || src[i] <= src[j] )) {
                    storage[output] = src[i];
                    i += 1;
                } else {
                    storage[output] = src[j];
                    j += 1;
                }
            }
        }

        swap_ptr(&src, &storage);
    }

    if(src != this->base) {
        for(size_t i = 0; i < this->size; i++) {
            storage[i] = src[i];
        }
        delete[] src;
    } else {
        delete[] storage;
    }

    this->start = 0;
    this->end = this->size % this->buffer_size;
}

template<typename T>
int CircularDynamicArray<T>::linearSearch(T element) {
    for(size_t index = 0; index < this->size; index++) {
        if(*this->get(index) == element) {
            return to_int(index);
        }
    }

    return -1;
}

template<typename T>
int CircularDynamicArray<T>::binSearch(T element) {
    if(this->size == 0) {
        return -1;
    }
    size_t low = 0;
    size_t high = this->size - 1;

    while(low <= high) {
        size_t midpoint = low + (high - low) / 2;
        assert(midpoint >= low);

        T& test_element = *this->get(midpoint);
        if(element == test_element) {
            return midpoint;
        } else if(element > test_element) {
            if(midpoint == ((size_t) -1)) {
                break;
            }
            low = midpoint + 1;
        } else if(element < test_element) {
            if(midpoint == 0) {
                break;
            }
            high = midpoint - 1;
        }
    }

    return -1;
}

template<typename T>
int CircularDynamicArray<T>::length() {
    return this->size;
}

template<typename T>
int CircularDynamicArray<T>::capacity() {
    return this->buffer_size;
}

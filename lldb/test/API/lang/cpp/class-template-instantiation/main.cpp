template <typename T> struct foo { static int x; };

template <typename T> int foo<T>::x = 42 + sizeof(T);

template <typename T> struct S { T t; };

struct A {
  template <typename T> struct bar { T f; };

  bar<int> bi;
  bar<short> bs;
  S<S<S<int>>> si;
  S<S<S<double>>> sd;

  int size() {
    return sizeof(bar<int>) + sizeof(bar<short>); // break method
  }
};

namespace ns {

template <typename T> struct foo { static int y; };

template <typename T> int foo<T>::y = 10 + sizeof(T);

} // namespace ns

class C {
public:
  template <typename T> struct foo { static int z; };
};

template <typename T> int C::foo<T>::z = 20 + sizeof(T);

int main() {
  A a;
  a.size();
  return foo<char>::x + foo<int>::x + ns::foo<char>::y + ns::foo<int>::y +
         C::foo<int>::z + C::foo<char>::z; // break main
}

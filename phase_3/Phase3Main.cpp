#include <iostream>
using namespace std;
#include "BHeap.cpp"

int main(){
	char K[6] = {'a','b','c','d','e','f'};
	
	BHeap<char> H1, H2;
	for(int i=0; i<6; i++) H1.insert(K[i]);
	
	cout << H1.extractMin() << endl; //Should output a
	
	std::cout << "START 0:\n";

	H1.printKey();
	//Should output "B2:\n b c d e\n B0:\n f \n"

	std::cout << "END 0\n";

	H1.insert('g'); H1.insert('h'); H1.insert('a'); H1.insert('i');

	std::cout << "START 1:\n";

	H1.printKey();
	//Should output "B0:\n a\n B2:\n b c d e\n B0:\n f\n B0:\n g\n B0:\n h\n B0:\n i\n"

	std::cout << "END 1\n";
	std::cout << "START 2:\n";

	cout << H1.extractMin() << endl; 	//Should output a

	std::cout << "END 2\n";
	std::cout << "START 3:\n";

	H1.printKey();	
	//Should output "B3: b c d e f g h i\n"

	std::cout << "END 3\n";
	std::cout << "START 4:\n";
	
	H1.insert('j'); H1.insert('k'); H1.insert('l');
	cout << H1.extractMin() << endl;	//Should output b

	std::cout << "END 4\n";
	std::cout << "START 5:\n";

	H1.printKey();
	//Should output	B3:\n c j d e f g h i\n B1:\n k l\n"

	std::cout << "END 5\n";
	std::cout << "START 6:\n";
	
	H2.insert('A'); H2.insert('B'); H2.insert('C'); H2.insert('D');
	cout<< H2.extractMin() << endl;	//Should output A

	std::cout << "END 6\n";
	std::cout << "START 7:\n";

	H2.printKey();
	//Should output "B1:\n B C\n B0:\n D\n"

	std::cout << "END 7\n";
	std::cout << "START 8:\n";
	
	H1.merge(H2); H1.printKey();
	//Should output "B1: B C\n B0:\n D\n B3:\n c j d e f g h i\n B1:\n k l\n"

	std::cout << "END 8\n";
	std::cout << "START 9:\n";
	
	cout << H1.extractMin() << endl;	//Should output B

	std::cout << "END 9\n";
	std::cout << "START 10\n";

	H1.printKey();
	//Should output "B2:\n C D k l\n B3:\n c j d e f g h i\n"

	std::cout << "END 10\n";
	
	return 0;
}

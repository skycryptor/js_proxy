function test_scalar_add(){
    var sc_1 = Scalar.generate_random();
    var sc_2 = Scalar.generate_random();

    var sc_12 = sc_1.add(sc_2); // sc_1 + sc_2
    var sc_21 = sc_2.add(sc_1); // sc_2 + sc_1

    assert(sc_12.eq(sc_21), "Scalar Add"); // sc_12 == sc_21
}

function test_scalar_sub(){
    var sc_1 = Scalar.generate_random();
    var sc_2 = Scalar.generate_random();

    var sc_12 = sc_1.add(sc_2); // sc_1 + sc_2
    var sc_2_back = sc_12.sub(sc_1); // sc_12 - sc_1
    
    assert(sc_2.eq(sc_2_back), "Scalar Sub 1");

    var sc_3 = Scalar.generate_random();

    var sc_123 = sc_1.add(sc_2).add(sc_3); // sc_1 + sc_2 + sc_3
    var sc_23 = sc_2.add(sc_3); // sc_2 + sc_3

    var sc_1_back = sc_123.sub(sc_23); // sc_123 - sc_23
    assert(sc_1.eq(sc_1_back), "Scalar Sub 2");
}

function test_scalar_mul(){
    var sc_1 = Scalar.generate_random();
    var sc_2 = Scalar.generate_random();
    
    var sc_12 = sc_1.mul(sc_2); // sc_1 * sc_2
    var sc_21 = sc_2.mul(sc_1); // sc_2 * sc_1

    assert(sc_12.eq(sc_21), "Scalar Mul"); // sc_12 == sc_21
}

function test_group_element_add(){
    var ge_1 = GroupElement.generate_random();
    var ge_2 = GroupElement.generate_random();
    var ge_12 = ge_1.add(ge_2); // ge_1 + ge_2
    var ge_21 = ge_2.add(ge_1); // ge_2 + ge_1

    assert(ge_12.eq(ge_21), "GroupElement Add"); // ge_12 == ge_21 
}

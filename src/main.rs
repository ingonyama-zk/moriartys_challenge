pub mod example;
use tfhe::core_crypto::prelude::*;
use example::*;
pub fn main() {
  //parameters
  let modulus_q:i64 = 4294967296i64;  //very large modulus
  //smaller plain text modulus (entries in plain text are modulo p)
  let modulus_p:i64 = 4096i64;
  //<delta/2 is the threshold for proper decryption, It is automatically taken into account in the decrypt function
  let delta:i64 = (modulus_q.clone() as i64)/(modulus_p.clone() as i64);
  //number of secret vectors 
  let k:usize = 8;
  // Polynomials are m_0 +m_1 X +... + m_{N-1}X^{N-1} and polynomial multiplications are modded by X^N+1 
  let N:usize = 16; 
  
  // cipher text vector of the format (A_0,A_1,...A_{k-1},B) each A_i and B are of dimension N and represent 
  //coefficients in N-1 degree polys.
  let ciphertext_container:Vec<i64> = vec![-2009650357, -1355939652, 850526365, -1021822524, -2118917007, -1708840134, -135511550, 
  -1830544961, 131863515, 615533652, -713489521, -890173810, 1382605110, 306729134, 332915549, 645969623, -2032167437, -932341364,
  510928218, -1780490474, 1942440859, 1871323104, 114946456, 150161185, -1539531150, 1726714579, 241712299, 1921668983, -1430234134, 
  -280837209, 271709565, -716349699, 1130122689, 1733136459, 412586846, -1991468044, -1890394055, 2116134040, 29870576, 1255159778, 
  557325277, -764174256, 1364346314, -1431430534, -356587619, 500628985, 68826374, 277380001, -42462550, 874795552, 1858435669, 
  -1626757273, -819351641, 1771662641, -2132464214, 1061423404, -692392355, -1265259971, -1771877955, 264534810, -1674055725, 
  1612762744, -619778809, 1777199426, -1112094328, 65221903, -1792344886, -1932479896, 294063635, -2096043434, 728345891, -912336073, 
  -1345083690, -1391440567, 1630733369, 1043026829, 293259789, 460875427, 554172552, -1952651887, 643547041, 252311173, 1183197170,
  -1957840568, -609296409, 1589886631, -1825150116, -408049048, 195120376, 1601021499, -110962683, 1387730315, -1957326012, -923002139, 
  -997581162, 902712477, -671631757, 1360362941, 1328248204, -1788470290, -1489817915, 2009183674, -263864601, 1578617848, -1568362832, 
  -406475604, 336566437, 86992080, -136648032, -2035724833, -1695264703, -913182117, 162530148, 1587177944, 900047679, -322716759, 
  509994055, -1992675655, 1235616490, 1538136002, -1095177952, 75068909, 1697258322, -1695457803, -1022580195, 360673216, -983518316, 
  96169049, -3350010203, -1106936982, -214866944, 1328632479, 1828557357, 3025330426, -2366017298, 1975078447, -3070561233, 
  549428156, 1387524174, 1135929862, 3218977522, 5573137376, -1532971801, -515160436];
  
  let polynomial_size = PolynomialSize(N);
  // the data conversion to u64 is mostly to make advantage of the polynomial op functions in tfhe-rs library
  // there are many add/mul assign functions that also implement the ring reduction X^n+1
  // note that all coefficients are modded (can be done in the end) in i64 format
  let ciphertext_poly_list = PolynomialList::from_container(convert_Vi64_to_Vu64(ciphertext_container), polynomial_size);
  assert_eq!(ciphertext_poly_list.polynomial_count(),PolynomialCount(k+1));


  //**************WRITE your code here **********/




 //**************WRITE your code here **********/
 

 //*PLEASE CHECK YOUR FLAG HERE FIRST, DO NOT SPAM THE WEBSITE :) */
 // Uncomment the two lines below and put the flag you recovered after decrypting the ciphertext
 // please put it in i64 format 
 //  let flag:Vec<i64> = vec![0i64;N];
 //  check_your_flag(flag);
//*PLEASE CHECK YOUR FLAG HERE FIRST, DO NOT SPAM THE WEBSITE :) */
}
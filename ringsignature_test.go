package moneroutil

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/paxos-bankchain/ed25519/edwards25519"
)

func TestHashToScalar(t *testing.T) {
	tests := []struct {
		hashHex   string
		scalarHex string
	}{
		{
			hashHex:   "59d28aeade98016722948bf596af0b7deb5dd641f1aa2a906bd4e1",
			scalarHex: "7d0b25809fc4032a81dd5b0f721a2b21f7f68157c834374f580876f5d91f7409",
		}, {
			hashHex:   "60d9a4b96951481ab458",
			scalarHex: "b0955682b297dbcae4a5c1b6f21addb211d6180632b538472045b5d592c38109",
		}, {
			hashHex:   "7d535b4896ddc350a5fdff",
			scalarHex: "7bb1a59783be93ada537801f31ef52b0d2ea135a084c47cbad9a7c6b0d2c990f",
		}, {
			hashHex:   "14b5ff33",
			scalarHex: "709162ee2552c852ba62d406efd369d65851777152c9df4b61a2c4e19190c408",
		}, {
			hashHex:   "383b76f631652889a182f308b18ddc4e405ba9a9cba5c01b",
			scalarHex: "36ddbd71a4c19db5ea7022571a52f5a9abe33fc00aafd24b562fb75b7fc0360b",
		}, {
			hashHex:   "3a170545e462830baf",
			scalarHex: "c381ea27500b61d29e9ad27add0168053cc1a5b7fc58b6960f67c147324acb03",
		}, {
			hashHex:   "190757c55bc7",
			scalarHex: "357f141395a76e2fd5003045b75f3216294eab0524eda1ed16cbe558145a2403",
		}, {
			hashHex:   "e1dec4027ccb5bf7d273163b316a86",
			scalarHex: "b365e89545402d3e7d649987127980ec8339af2e3067ff942e305a9ac0b7390d",
		}, {
			hashHex:   "0b6a0ae839214674e9b275aa1986c6352ec7ec6c4ae583ab5a62b947a9dee972",
			scalarHex: "24f9167e1a3eaab18119c225577f0ecc7a488a309e54e2721cbaea62c3db3a06",
		}, {
			hashHex:   "232849cfbb61443dcb681b727cdf7a2b84116dfb74a3c1f935",
			scalarHex: "8af86aa2f8739b7d384e8431bd1ec5a75a1e7d1dc67f2f7100aeffbaa516200e",
		}, {
			hashHex:   "0bd05745dceb00b2c18080e6cb66d9099e9610d620c188a9",
			scalarHex: "79b024435100e891c167abd8f96d3f5efc6919e5861f7298b7736f2927276809",
		}, {
			hashHex:   "ef2e5ce130838935ed202cd61453ecb860adbb903f0eb950df",
			scalarHex: "594cd0a2b135b1c29544b095b8a43e5b3cea1806fdcb9b59cc53829cc62f2000",
		}, {
			hashHex:   "48c7811fe63d09ceb4e6ad0acd51487496b7108d279078bb",
			scalarHex: "43ff71f4c9544c09e583d3fa4d21297463d029415e236ae758d06f4238b5ef04",
		}, {
			hashHex:   "854b5522f6a7a50af76e305c65bc65d2ad7603a00e244aabab4b0e419576c7b1",
			scalarHex: "20a8a23806bfa8ac1e3d7a227bc4c3554a18f5e593e5f8b807767c3f818ebe06",
		}, {
			hashHex:   "3aca21fdffbb7305feed286925",
			scalarHex: "995f4205c63106243983d2be160a2e17f2ac9b78c8e6a705a4c52d6adf2ada0b",
		}, {
			hashHex:   "5cf74e22b8b6d30b90be7e2296f1e89cb76bd7ea3001663256",
			scalarHex: "42138bd241761d92b67db8ef225347b98e10b74f6fb0123da7b44f8d51c37309",
		}, {
			hashHex:   "5eace33d8b54417a5bee734727d0dfadb4c44b7bbe71",
			scalarHex: "16e3cb1efab4c1871946790ac6dc5f54f8880aa66cab176a42fb1d5da89ef30c",
		}, {
			hashHex:   "1b78000e7cc0de64a8db20dc8b10",
			scalarHex: "359cb964fe23ac02a1693f86bc0561738ea569f502f6312879f96d1fb1a22a01",
		}, {
			hashHex:   "5fad29a0af0ac0bec3450ce863394a7b9458",
			scalarHex: "92a8c81d5d08c480f39430e366f5d9bbc7f8210bbac90f78ee2ae8b5588a9701",
		}, {
			hashHex:   "353e9340e9",
			scalarHex: "e5b47f1d528661666dee909b8159ca5c3ea6dd6064ed22651f5398e0dba24e00",
		}, {
			hashHex:   "9de61bb6f3d5075b59fa9ae86a8df85b7e60efbe1969046e4f863f302d44",
			scalarHex: "0d8ec9d8b735139232ff5cb99a5f528cd829362912c43c7b029049ab72b1c80b",
		}, {
			hashHex:   "8028d7a78fc98370a58876bf4eae360a99c87df0162959d6",
			scalarHex: "34231faea4f4a7b3f64d36be7a5261a047d063ee8b9b04bd58a03f8a3ecbeb06",
		}, {
			hashHex:   "b2226a11ee05a48e89f210b9d3",
			scalarHex: "83f43546f7189d4d7bad92b0d2648c8aa59d70f5a2610ecbad2a029b9ce7e308",
		}, {
			hashHex:   "232ef1768d8493f64ec43ac0e80b986060d47f5780d52ff3b9ee",
			scalarHex: "cade3388d2686f20d6d06a41e20c5cdb67f7ca43c4d74dbc5c3c1f25e8f7a902",
		}, {
			hashHex:   "1dfd925486af17a4592fe31b84d9e1",
			scalarHex: "beab6d2da76d26fd4937ffa102298a0d69ebeebf46255b3e9387131873994403",
		}, {
			hashHex:   "07bc8e67666d",
			scalarHex: "90581961337ab4b806082f6d3a1d297b2ee0fee11effb28a14b77207190b7808",
		}, {
			hashHex:   "2d219d894b5c0b55b5d078398ce0ceed3837",
			scalarHex: "7c923555938a33b877edf8ecb9b1eb6a1f90d6bdd54ddc3a978ea1b297563604",
		}, {
			hashHex:   "d96e5fe31cf5fe6cd09183cf7e7df5da577800aee9",
			scalarHex: "ea51b9f3b17073f8db2ed169f8ac25474dbda5da733be3c4c8ddb74a26eae509",
		}, {
			hashHex:   "b254e7824ff4370acb9ab1d8694351671e600767894b",
			scalarHex: "1831a736fbba5833bfcc73720ecc7f6b5d3ce62dcbf420e55fc94f00037aa70d",
		}, {
			hashHex:   "357c6b0ef93cf0097c372da0fbe831732ef9",
			scalarHex: "1d6a6295c81f8ba4888028930ae09e2557b43abcf1c9f7103fe1a7594f346006",
		}, {
			hashHex:   "b7202cb7468825d7d4258168636ed1ec",
			scalarHex: "30a42478c3a42463a5bab1a0c1d4c0d3c51bf1f456b849a3d826e93788f9510c",
		}, {
			hashHex:   "5c2023e9ee12a2a12bbf545e8e4038a177fd07bcb2e768ec4259d306d3",
			scalarHex: "b2c18f7b74bcfd547362c45483beda13efeccf38602c16103eff8aee1bff3303",
		}, {
			hashHex:   "18d9e94418064ca5f13386224d7e01",
			scalarHex: "db6c9680294cc20cd83783927563fe2c19e1e30462d02628bb187c6d43aa0600",
		}, {
			hashHex:   "f4b63131b4d5cd7749f1b1e68e9533d522822c60",
			scalarHex: "a9be8f15d3daeea4df114d957a15a3f7380fae58508a19156af613a692598507",
		}, {
			hashHex:   "c54e0f7e67b561",
			scalarHex: "1ade1203c88d0959a4e0494b48f31a32d1c7a1065b83d0d86a4232da6738a504",
		}, {
			hashHex:   "2554f6116a35f493070b17654a817eeb55e35cd16bf60de0da33abe2",
			scalarHex: "53df47b8cbb269cd78ff4a9552549118e8fa22011c84030c39cad8ac73aecb06",
		}, {
			hashHex:   "0c904b4d59a3da",
			scalarHex: "ad232a646445a83d9b1c7c5b36363b1037b209890269629bd3d7c66d9d9a600f",
		}, {
			hashHex:   "334a",
			scalarHex: "1ab04562c0e3238e41e3e0de165de27b1c35e7a16d7720cf8421d5969cb0d503",
		}, {
			hashHex:   "1bd3aab0e9098d",
			scalarHex: "77f45ccf9905cf5aa4d701f4a333bfe681520339288c871c61aab5d08472c606",
		}, {
			hashHex:   "f62cbf2feb184a",
			scalarHex: "4274412946a00971c1d225daa1c657676d1a453575164043ecf1675276bda605",
		}, {
			hashHex:   "8de6d27a8d670b4e0c01f58f552a58d611250f663786eb",
			scalarHex: "43792a134016bb75c6e15165564fd3aef676dc5a716eec6476494498cc97b00f",
		}, {
			hashHex:   "b593ed9a740bbc1ecfe84b59007f87d6e665f5577bd61ffc78b6ce",
			scalarHex: "67a5ba0d8036c19f2f62a19739c86a0945ddf34699f617385771d54d3979c80a",
		}, {
			hashHex:   "0c6dc0e23711d7a602c4c7aec292588c634a11a40eee3aecbf",
			scalarHex: "f703568d1af5f8621bb54debeeceba58f971173c4889d9ea9ab34cf849307606",
		}, {
			hashHex:   "d27bed385fd5ad43e0b68e13ce5aa83476347723c37e9d4d8c65",
			scalarHex: "c849758dbb70eb051fc38304f35293c08b0d127cccc705f1b6b6e777ba65bc0a",
		}, {
			hashHex:   "ef7658d663e1cf95ee2a8be65c09f1b69e3f788bd81121bc2a1616",
			scalarHex: "9e9b4600ca904414e72a682bbd37598c58db6b058bf59786ad9b30941568c406",
		}, {
			hashHex:   "c163fbabb36fbc32b7e24cf5ffe4708e0ae9",
			scalarHex: "05cddc663bd5d8193bfc9727e0da5daaf3077c68b423031e15c3d2bf8b677708",
		}, {
			hashHex:   "30",
			scalarHex: "76508f84081e3fd53ad1aa29f1878ba0e8fcb96542a07186fe3aeda6bb8a110d",
		}, {
			hashHex:   "a29a8ef14327373356612a",
			scalarHex: "d1d73866b223af5f438ab1124b6eaef73fc7956bc137181f46ffaab5b467c10d",
		}, {
			hashHex:   "c47118180f0229dc185344343bc9e3da51",
			scalarHex: "fcc968961386b6f882c9eb51af6ae23c62b5cd8e75b5d840c0cf9814037b4a09",
		}, {
			hashHex:   "55fa235eb20659e9bcd5812cf2b78167",
			scalarHex: "34cec87f2ca28e65c2dbcfe9e9e16c852b0c3aaf9b439c05cc4a38a089095005",
		}, {
			hashHex:   "ca1e303fcf3eb492ec",
			scalarHex: "ebaab9d272835327348847e95e4f7b0bc3a15927886847317a0a0f8db7859c0c",
		}, {
			hashHex:   "ff416888c2c8558a58d851dcf264be1dfb1ae457d0866934ba5ec625085bb030",
			scalarHex: "8364b9ee560636a247dd57f5bfb868b5a35ef3446ea3afad8e105411f9b97c0c",
		}, {
			hashHex:   "f7115e63ee9d6ffdf1c26dacd8eb812013a5ed3db9b77e8af0",
			scalarHex: "df5f1e2aee0001ea8acbf13b93124e14dcbe3da07e25996d5d3f949f927db803",
		}, {
			hashHex:   "0c9998e1",
			scalarHex: "ee8ec14e54b6ed263d460173e6f0fb77be135b39eeb60f3234f1a81de956bb01",
		}, {
			hashHex:   "53472086cfada41b94cf6527d73b9b78ed8cc2b1ce",
			scalarHex: "61855885dbd658eb2ae21bb805f33e28bd0a9ed4ecbf7259b5d2534965822505",
		}, {
			hashHex:   "259bdd4f7243ac81af3d38ce85eaf44e5c625f8f2550482cce4d",
			scalarHex: "0d5c96bca1bddda05680c334d6d9a21152ad737cfa6298dd4b25eb82a8a31b05",
		}, {
			hashHex:   "1efb9ca4a4cc93855f3a7bd05273eb9c",
			scalarHex: "461604804edbc7992d12fcab79cc6d9daf2c03f92802ecb265317202ddc92f0a",
		}, {
			hashHex:   "7108691aec4e4f93404b90a090",
			scalarHex: "f1d4e4e795afb6fc23c2f3c1e7b23e75c5f19f322c64c772395bdcf64ba09504",
		}, {
			hashHex:   "565be5f229431457ced75ccad8658090b8edf78a24562d1db4ef2b85",
			scalarHex: "fa38706d92f0f2bdece41511c6e045aa95c0671702669d3b932b11c43b904604",
		}, {
			hashHex:   "c7e95dad3d9bcf",
			scalarHex: "14fa25063cd5e96033dfe7a32ba043da12c0712e6ce90bcf39aa0eeac24f4702",
		}, {
			hashHex:   "c0c97edd83a8434e616077150863c3c69555c0501a0dfaf6b9c151c81414",
			scalarHex: "f6ad267b0716dc92078263f581841c28665c4e203608afed703f99bae02c1600",
		}, {
			hashHex:   "92ba274b4317",
			scalarHex: "fa0d73f933a67d702616a7e971e5af7691dbce2d2cf75e4d7fa7d62172a8cf06",
		}, {
			hashHex:   "3a7cecafe1edcb4367",
			scalarHex: "89b3d092c7ff5c08dc9f51c31effdad4b2cf456a292ef5f94b556fc6b8db8805",
		}, {
			hashHex:   "50db589492127215ea94e9874337c9cfb41b9ffb88f3",
			scalarHex: "3e149a3cd272414001f6e65a3eecd712bf4172c670b495b770bf697811783305",
		}, {
			hashHex:   "7b584c05770804795c0d79f7b8da48b1e1002c0fe1",
			scalarHex: "dd78767788e8a5c4f1b4033c72e627ad961ae58d3515a69420c44dfa76a1dd0a",
		}, {
			hashHex:   "7225eed4946a3f6c8ea5ac19ba16378d972e",
			scalarHex: "f5f24267d4cd317081eb6f99ce070341272e822879ecade4647dc951687de40d",
		}, {
			hashHex:   "db9907f24b3bd51cf00c16dbe891f977fda8355e89d84cc93e27387bf5d0f6",
			scalarHex: "73c5bc311b3e0c909695ab4bdc8c890368e1d2661a959421ea6bc25b36fff80c",
		}, {
			hashHex:   "e169e0d3f0929e3bfe48",
			scalarHex: "a21066739e97040b07171668fac7e2fc67a3cb48912bfa281a8795f1a3edb307",
		}, {
			hashHex:   "45d6ec9c7816eb98245f6b3fd3b9ab964f15dab879dfa141528c23",
			scalarHex: "4b37059e4ee7ebf7d3f74857d5a9f53cd0f30d39e42e3ea286c4e8728039410e",
		}, {
			hashHex:   "2b4fdbdc717ca646d5a60f3693ba",
			scalarHex: "20b1230cbe3d9dea3d6abf74cb628aa57e56876f03a4195cde0df6860f8bf40f",
		}, {
			hashHex:   "15b4f3f5690d",
			scalarHex: "c069e453af981acaef67950c981a02d884593cbc99df2fe4b43c8e1c52959a07",
		}, {
			hashHex:   "96c0df",
			scalarHex: "836d3f7e21190d609b8643cc96ebbaf81d48cd8190465e42d588de817e3a7e0b",
		}, {
			hashHex:   "a186e340580cc91ffa068f7cd430",
			scalarHex: "27144f0857f8a016035e4190c052b1316ca176eb5c2e85820a65ebbe806daf0c",
		}, {
			hashHex:   "f5e78d9406ed27bb12890bd813abc82f4f",
			scalarHex: "9afdbf19ebc041bc0231b0568b0bcc1a836b928be14742e1cdf615df2aff0107",
		}, {
			hashHex:   "4d2454359907302b4e40241a0f8347",
			scalarHex: "0ad36e4098942bd724f0c0941267622f3d274106c8c02a34329cf15c20dd5603",
		}, {
			hashHex:   "aeb8bb7c2c584d3d7f682296a238b538",
			scalarHex: "cb4b44f7806090f507e928ac575c66fbfb87750da2c025b4ec68aedcc8ac3d00",
		}, {
			hashHex:   "100fb9eb981f0c2f4bba26c83dc44c43e59ae04d1d7d",
			scalarHex: "573bd92409cc04fec79e4d7f894d8300f955c9405aab5965394ff8ff3442750b",
		}, {
			hashHex:   "a83ae1487dbd2951bfd935b774c0fc142dc20012261e4899054027c9",
			scalarHex: "0f01eec9f6adfe6992f10108501d15aa9748373dd844e572912dbe2f50056805",
		}, {
			hashHex:   "f27e74638002f1d760b8cf98",
			scalarHex: "489a7c1a264260ec5eee7826bae93bab2dbcf3205495c58d083bb4bffcdbdb05",
		}, {
			hashHex:   "775066e50e5932dc",
			scalarHex: "42f0cfe1866ebbbd2fca91c6f4282e51231c7a1bb87a40877259c4e0a6dac20b",
		}, {
			hashHex:   "ebffa1366f60830cf937a4",
			scalarHex: "c10ce7d18d6d8044abe60e4cdc6ff4a741cfb0c42f64f5beea92f93e0977d506",
		}, {
			hashHex:   "a5a5db7965a568a3f40486db7e75ceaae1c2",
			scalarHex: "04c4db9817c16017a0098d09c2e30771e177d72c008614d44dfc4690db85e708",
		}, {
			hashHex:   "b2f951c2ef4eb6b861c11987f274290374ee76047caeef37122a",
			scalarHex: "a069a11cba2b439db896cfd2eee3f105e8f041ca0738a0c2c8ebc7a8b66ba30d",
		}, {
			hashHex:   "dfcc51417d649ae882f4808735a9c7c37740bcf2e13522040c25789c0aff",
			scalarHex: "896eb37d75c364f604e83ea61a95f05b18acf107eff1921fb1e642d3e2a6970b",
		}, {
			hashHex:   "ceb73372a26d746e05af",
			scalarHex: "c570ea35daf569a461b967c2efa4da13fa5edb946ccf5566596d660b83ce2208",
		}, {
			hashHex:   "c4e9946c0aa2cd30ef6a3240c4",
			scalarHex: "a7ede14f04d0be893e89112a6d8c10a413d67b4204dc55acb80518cf8014d60f",
		}, {
			hashHex:   "5d72b2",
			scalarHex: "c19fc129dd596bde9bb754939432373e815b53282c4713d070b62da12da65600",
		}, {
			hashHex:   "d87437bda57d",
			scalarHex: "70a13729a8c1b392ef88c8a993e70de5f0e296c81e385f26b2fc9f945bd98003",
		}, {
			hashHex:   "661a3e0638e7bcfa422e7c9a7397",
			scalarHex: "aa639794ac5338a17b01d238bb3d1324b7cc74d22d079bce5168c12bb04fce08",
		}, {
			hashHex:   "e0d812121ead98c24de333cad29b9262",
			scalarHex: "43b6986c5d110f0962d63229a9b094823888d552ab79a54ef37a123d983cf102",
		}, {
			hashHex:   "8e1601f8b5ca5d7bc628eb1194632a56",
			scalarHex: "ae021df344beae6f378a362a345307f0f5dad97490651e09e8f58d44c8047300",
		}, {
			hashHex:   "665ec2573f172d978faee2a38caf047658c09a9e132d531b9b8facd1bdc5",
			scalarHex: "15f6cd046611f0728b851cad6b9d25ec806cdd3532b18c1813dc5c223ff3c90d",
		}, {
			hashHex:   "0816e8cedc2c2ed8c4e73a0c75f1c4e44f",
			scalarHex: "f26c9f8c1b7b1427b4d86d3b0a3d466279785808311aae09a0ebbcd1ec137e01",
		}, {
			hashHex:   "f5e03baaa35f4ba8f8a3eba410a4ec4aed4a3bc04f",
			scalarHex: "0e5800bd88f749467b701ce4686633729aab3ec5e579a0c828f4d98f2c9cd200",
		}, {
			hashHex:   "da935a9fd2",
			scalarHex: "c3fc1f02037e304100e400a4cabace7323c4ef310b2440aa245de2ffefd13105",
		}, {
			hashHex:   "7451f59656b0957ef45c",
			scalarHex: "fd334a1f172e18a74951df43b982da3d19f9a8976b213f0b91c4b6185a58650a",
		}, {
			hashHex:   "b017e544ae570afff65ff021c99a975c251c",
			scalarHex: "74c7ccef39ef8d37ece8fd5243f6f0607c19b770689ce26a88cfcbd212570a08",
		}, {
			hashHex:   "ac47b35782a7f64db920b36df228b6",
			scalarHex: "295f8eb09b9358a6fcb867cbd5e33dcfc41ebb74c2dbeefc54beda5d13122800",
		}, {
			hashHex:   "80af",
			scalarHex: "9beb9f8f9d5d9444e3edcf2291912112a691f99bdd8e0d8569790ba12e3b0407",
		}, {
			hashHex:   "380eb97f71e767e54dd449f64c2c3da7b42f538a5e5345cdb860e4c20ec4876c",
			scalarHex: "ff427ee8d2c82415a8da920e6e76ea1de4ae4414181543eeaf06f381ea1c1805",
		}, {
			hashHex:   "cbb068a11c73c6b41de059df9e5f4c5a0f03d986",
			scalarHex: "f065d97fc9c76206d663c6836ea06c165ecd1886e068af80f36ab8298c56860a",
		}, {
			hashHex:   "779b186094d2",
			scalarHex: "5cf25b8ca4484a705cb96c2f9858b683e740836847238d1f170ac4065fdb8203",
		}, {
			hashHex:   "9b3f73f3a0115149352fe28dc8257fe9ca718f429df1",
			scalarHex: "5c59767888728b36e55df62deae6869c98458a09efd0c955ab8904a6e634f409",
		}, {
			hashHex:   "152a",
			scalarHex: "6b502eb3f8f827421e6a42255fb2a5cc2d63141b5978ba0857c101fde8525a00",
		}, {
			hashHex:   "ed7e73548a53a9b2fd9dbb654b5266c13ca5058a557b5b1225",
			scalarHex: "ece34f5870f7a67e7965d8be7fd80c006ed7151ef42bbca1b69acf7a139c0a01",
		}, {
			hashHex:   "5cc8d09df6d47c5283b37276f9c9395e7f726feeb6183978",
			scalarHex: "3bfff6a7a8d469def6630ef588be7337aaf36686b2e73727f1458fc92b0d6c0c",
		}, {
			hashHex:   "a8",
			scalarHex: "e6f0a9b10c1d094f963f56cb5227e539c4e8496a44cbda7c25bb261e46ed8202",
		}, {
			hashHex:   "0aeb",
			scalarHex: "eecad9335482b43600ef5f9b5db3d4bb46cadc354b2f21952c6711486c91ec0f",
		}, {
			hashHex:   "6b39c85520edd76b98bd7321794bd6ec67991cbd881f",
			scalarHex: "7da35796d7cb0b903e1036c659bfb08dd593f87ec41206bdcf0d882a4b346d0e",
		}, {
			hashHex:   "2b6d3db208b00750c01dfe16ff62a27efe60f489703922",
			scalarHex: "d86df18758aa31c662227c15ebf1853489bcf6c204938bc17f655833366a830c",
		}, {
			hashHex:   "b05c8a5914d7e162",
			scalarHex: "9541937576470e144ca3c17ee32a33135fb93172414ea9d13cc8e349455a8b0e",
		}, {
			hashHex:   "d9622b304b65727d00199d4be8c831",
			scalarHex: "2de3e6006a784167ea3c33d58276340f0e30d9d2d3f01fd85c7f2a5c58846f0a",
		}, {
			hashHex:   "bf6b755c110d5b",
			scalarHex: "4419f814c031ace7f64390b287762c0584a87d75bf9bef8960b971d048a5cc0f",
		}, {
			hashHex:   "1300bac6c13a286268776bfdf29ebbcffe8e9c23d82579d4",
			scalarHex: "63cb5a78d23cf810b5db39e1b9d48d7f1f3cef09d75258eec0620da463bf380c",
		}, {
			hashHex:   "5bd2b43642d73f52c4bb1ae2eb8098a83a10966efd41aeb806",
			scalarHex: "5ad6470ed0809bccab0a23fbf84680d1a9e8dda4cf002c5a862d7c85c7c7e50c",
		}, {
			hashHex:   "d8f45daaec7d2b206d1986f4a6aae33a0586e14bf8535a821c71",
			scalarHex: "3bedfd95b29748a4100884499499dfa2695acb6d8a47a2c0953cd7cae157c302",
		}, {
			hashHex:   "c3d9a1b8a7cb0a87edd3",
			scalarHex: "0eef8631cda551dd21303f5a11d1c96b95490d456a86c5e4637933b546734f09",
		}, {
			hashHex:   "34f22eea2cb6d61c34441a123b00",
			scalarHex: "0b754b7586d97a1a88c811bc226eb9b449a86cb30b63b60184064ea75ae1c802",
		}, {
			hashHex:   "ef94ce0429a249bb35558eb7d938",
			scalarHex: "68d8870d843a53805e12cedc33f36fc87f842140bf3a03a6844d3720b11ca60d",
		}, {
			hashHex:   "e82de0d397",
			scalarHex: "057343ec548dc6d73a0e432325cc731b14cfa89c74d4e021fd942b4db09d7d0e",
		}, {
			hashHex:   "0f7d",
			scalarHex: "84bed632adb4581c474dadd7d140e55b7127d5e13ae739bedc06c9cebc5ec009",
		}, {
			hashHex:   "f6a3ee600e9ed4de45b4f6c26cf41e24bd23e4af",
			scalarHex: "c49b184a8132a18e91ad8b220ef96946d94872ce96a5eb337a6f783d59ff9809",
		}, {
			hashHex:   "af6e3b59d9110d86eb68e17dcb896a40edf9095dcb6018",
			scalarHex: "083fb34ab5bf1ac1346bd7dcba952113cee7d453725b469b49c87f045472600f",
		}, {
			hashHex:   "8c773bbe4ed39790645b5b1610362afe6a345221acc8ca4cec",
			scalarHex: "42b4ad7a7b808940449ab70562f881260bfbd1ecd1fb3b37704e8a3d50dcdf0c",
		}, {
			hashHex:   "9b0b2b",
			scalarHex: "96ea25ca64efb98b69e3f8f169e37c1d75910952fa3235a5e9dffe08d7772804",
		}, {
			hashHex:   "725bca",
			scalarHex: "428633c15cda9855daea0e592568a792bbda7665b6b8e4f5d13adcd0d8965005",
		}, {
			hashHex:   "1b",
			scalarHex: "08e751d9d7b92af99948db9b6d14e515bc12236c2d3e589d2a7adf5ca69cc906",
		}, {
			hashHex:   "17bb25a331548082a7a17ced5791ceada62b90fd4742c5",
			scalarHex: "361977420abdef31c10abb4af20fd2dac631adbea4c63ae738799d264650ef09",
		}, {
			hashHex:   "1bec40aef4f9a903ef1a92f66eee56851a25b46557c553cdd15f",
			scalarHex: "0b7df89e8a79be601c642e9d825ff6354dab55225ca53b5d8859399099605c08",
		}, {
			hashHex:   "ab803bdbfd413fcb178dd13be1c86d7f854cd4c35d0ff1",
			scalarHex: "24c8e355e2240b126d2e0083df6937ac59042ba9c0ea53ccef49304a2e350905",
		}, {
			hashHex:   "160ba843ef0f7e51",
			scalarHex: "3892d64338498d5ab0f4753d4be70616a169f9f0c4039606fbbf507969b4b102",
		}, {
			hashHex:   "35de90dd5717adbf5143884947c12a9aaf79d4a93668947514",
			scalarHex: "6e9e42fa89172bb8d6291e4f99b1730ff8858cfa3c2f4b5bdfc1e54c4e3a1e05",
		}, {
			hashHex:   "078948476863961dca5823db0cf1678152",
			scalarHex: "0b6b05d724384379afccd70c684ec7548c3902559e05d88e4bffaea0bcac1306",
		}, {
			hashHex:   "a0b85d805da9a0b16616",
			scalarHex: "3ba856fe17f975c5bb6305cc97def0f6de845fe14fdc4fa39dbea97d5a839200",
		}, {
			hashHex:   "9b007e9d02b504b40df12c89f19eb3265256a96adb5d4918dc399a",
			scalarHex: "80fc823c8b61de2f2bfa9df0f7b9f500aa7ec2d2f9e598cd40bb2ed55716e406",
		}, {
			hashHex:   "5ff142",
			scalarHex: "e8e0be7910f384fb05593458d3a0a50cd3720485451a3b88fb766d6eac1b0a00",
		}, {
			hashHex:   "693a93fb3166bdcd83a0700e4352",
			scalarHex: "649b6bc56ebb4839dd21332d26078c0d11a0eba65f03c3d0cf72491a0cb77e0d",
		}, {
			hashHex:   "b38ac1f0c87e1392f779626f33f60c2e77",
			scalarHex: "6421d6db09ca6977159c66ad759300673add3f8283d71191d2be8d0e79f1c008",
		}, {
			hashHex:   "be91",
			scalarHex: "109a614c8fb4e62bb79fd47ea1727c4a0168f986cb81824fade9432d0c62c40e",
		}, {
			hashHex:   "17d5115b1d4b1c43ebecb63401b34fd3c297b3db7ca643652d",
			scalarHex: "7ffb834a8b227f59dd55b2fb016b0ded3a0790783d739dc96323f345f360af01",
		}, {
			hashHex:   "e6bac81e3e4c847072a680ad7c1979c2a6c2e8fb128ba07f2c",
			scalarHex: "7a4ffaa201b57450d40534137de8d6c87e1d4c1f3391944de9b923e998ddc309",
		}, {
			hashHex:   "6f",
			scalarHex: "4ae3bf858d2ff2319e508f65417f04f638c47e1bb887f095340cf5990e7faa03",
		}, {
			hashHex:   "b44166b9fb6db4159f62d9a7be28382db0a19388",
			scalarHex: "660e7d09e1bb69c1fcc4f1f2490477f64492cbb6f05a1903615f31bec0bbab0f",
		}, {
			hashHex:   "85da49ae04daa5c0b9831589949d81c0f17bcaf2442127de86f8a2e746",
			scalarHex: "98fbdf1a67dd0cf6dc1c91a74768fb359fe769103c3ca863b95c891166c1cd0a",
		}, {
			hashHex:   "b85fbd72a3979f",
			scalarHex: "4a169f233c6addab01e9b453a0d850b3339a09ac09664bd70ab5d79809672c01",
		}, {
			hashHex:   "36d5b1d708adcb70575333f420461948ba3b507fe164",
			scalarHex: "ff27646bb052a292a3974559573541394e2a7510bd55a146eccb8ca05c07dd0f",
		}, {
			hashHex:   "a27f52eb72b60d3b6ec81ae07a7a328f745619996d045b732ef1",
			scalarHex: "974531b356b20641929e9844f53235c7b28b9722684d6559f7b9fc8a054f9405",
		}, {
			hashHex:   "96718971be",
			scalarHex: "5e45bf2da3f5b2b8e4eede4169383c64a3b9c9b0df5923d7aa46838269bc930f",
		}, {
			hashHex:   "c0f7cfa5e8bbd2978d94ed92d4eff4fb954df38d",
			scalarHex: "6e55ba284a3ddcd385aec69383dee4063cd8756b49af1dcd9fe26bc3bd056509",
		}, {
			hashHex:   "bd437d980037653f5fc415d315660cf7e2cf9c89b2a18355",
			scalarHex: "3957ab6326f2537208f79f6b5ebaf62ea237829e63978b77ee32f061da56c208",
		}, {
			hashHex:   "4ea94802dc4c93f1bc53b2e497fc618c3da4f6cc62a4ba7fc4670c7efb5bac",
			scalarHex: "09484d1749c22cc58421109d80b7ffa1cf90124647e00182c4afe4249d0d7201",
		}, {
			hashHex:   "82b0849db242",
			scalarHex: "f4c79e1046d081d66e3baa457d0e086947b830cfa2e0fe8941ed078d634b8b05",
		}, {
			hashHex:   "5950f8db130538903b0776548418c66b8e095e6fea82",
			scalarHex: "f72d09be4c76d934b81aad5f6635e1af20781d807d8e450deb895edfd50da10a",
		}, {
			hashHex:   "6cc1024c7a83ee38f5d1641744163588be640a9e2ce2468a76c682",
			scalarHex: "e78596ca4f06036bd51939e877bfa21c8905a41f3f3c9e2d7766a5543a9dc30d",
		}, {
			hashHex:   "fa773a9336c95e",
			scalarHex: "b5a698e364aafc7333992ec3aa89cb17ed9f9c99061eab037785dee5be3dba0e",
		}, {
			hashHex:   "86631b2628f0eca1a720b52d23",
			scalarHex: "0d441df30234fad12ee7e2aa1debed64135b768d87820e5d1aa8106b55ff580a",
		}, {
			hashHex:   "59",
			scalarHex: "9a2c5f9025f1f0333863704310875ae81a574171bed5b047cfc0f50e347f630e",
		}, {
			hashHex:   "c7f433540c23b5f64a42a35d27180c0e92c37f10e0a34ed94147e88f8d707c22",
			scalarHex: "1ed70274e0fe09a11cb9f2560f6b702c157dd7d3be105359e749e3e6f1d8d30d",
		}, {
			hashHex:   "8b888f09148925",
			scalarHex: "70e549663999f2e41ef888bf02f6e5678abd283cce8c6edc3c3f716ffa1abe0a",
		}, {
			hashHex:   "04cad5265e2886e4f2857ff484cf15f37e0da57a37f9b245f6",
			scalarHex: "baea80671a6750fbce4ae7e4b0e47fd40fc2023fb4369b81f9cb43f16939e90e",
		}, {
			hashHex:   "7f1a66f1f459c59b182211cda8b35c3afef6522915b68a6ac71e4fdee38f",
			scalarHex: "9db92a0b07e6982f43845b8e9b7870f1ddfd5e3c82fc37627fed9ebee4f93e0e",
		}, {
			hashHex:   "6a3b39aba44aa65c99",
			scalarHex: "23ca5981817a5c50f84072fd41e103da99e76dc498a87daded12a7311159b30a",
		}, {
			hashHex:   "2d2322f0bb1fa9ec89c24f54e576a75b8747d641dc13d7082351961f",
			scalarHex: "bee17516c0844cca19a099615096d5e55e6b5e60f63a1d48d36df3451878650f",
		}, {
			hashHex:   "ab8277f0c90947fff12eb084fd01395c01d8939e3f337c26f24c6203",
			scalarHex: "2ea5f553b96900350ea88bc05c5f2e5967a8db938a2340c5132289a92932f90a",
		}, {
			hashHex:   "c921a1",
			scalarHex: "85b72ad57886613e35468c5230238d0034883f25e7cc691f6bf599501489f102",
		}, {
			hashHex:   "7b813af5137c2612f81a6296",
			scalarHex: "1aa2d4a7996acfc988b271d6168eb8497367a818b13a705e41c480061339c501",
		}, {
			hashHex:   "495590e02eed7b18edc8301f691a4edd47f1ed",
			scalarHex: "f3583733cf0e2d5da90c3cb96d7447636ba20d13367b61318aa1da103672eb01",
		}, {
			hashHex:   "c423ef60849a8ac85b45d2626d6d9c0e1613ece981a27f57e638ac",
			scalarHex: "b4f6f97dd892d9124ff7d7e22f97a1ab1790ba2f5ae73638e20d6a1079b86f08",
		}, {
			hashHex:   "f3595b",
			scalarHex: "19ac121f0458478e817db36c7c405b93a93a9bd0a6cec2e38a2165b8988dab04",
		}, {
			hashHex:   "d4b819e735c3d86b",
			scalarHex: "c173e374fdfa3a2ee4cc9235c9f1a3288ee1f43d6b8fb21dc9031fa5f59e2405",
		}, {
			hashHex:   "67b70bead5a15b5de58743d15319facfb56596c25d2ecd1cbd591b6f56d6fff8",
			scalarHex: "fd1fb9efd2d642ef2fffe98d72012cfc8896b229d4fca3c1130123414a9d6800",
		}, {
			hashHex:   "32bfca",
			scalarHex: "9e55322532b249691cb11800cdad7af669d91542ba3a22e3b36bca3b3f125300",
		}, {
			hashHex:   "64dfdcbfbecec7d20ef84e278df1b48c4d6b9f74fd",
			scalarHex: "ac2a2b5e9be42d4671b03688863b2fa4ad2c4a0edf1aea3b655a9628fb93b409",
		}, {
			hashHex:   "8ff1dd65b1691e91a904c1b01da6a7b6a97838f0",
			scalarHex: "c61d80faf26ff15f9a3d49a5f4b3f36f35a6dc246e00d9ccb97ac15629b81b0a",
		}, {
			hashHex:   "8f3561c1",
			scalarHex: "e6f25b4bbf45727c430ac7283edb9e782afeaef24557104120d598fb14952c09",
		}, {
			hashHex:   "28ab0fee046d30114632d1a8301e3f9980979cdbb341f208",
			scalarHex: "9d005df0be511481510e2489807ba5c0ea92af255583f2cfee6cff1a182c5300",
		}, {
			hashHex:   "d99411adeaa051c9fc5c1225e59c",
			scalarHex: "b33a824170a84d97183353c0e1bc4ecacdbd2619c5495bd903b4be0c91b5c405",
		}, {
			hashHex:   "b652da",
			scalarHex: "d3d4ec6770a6023fa910c28ef9b063d933a089ea5be57488a7a24b415be4f206",
		}, {
			hashHex:   "7edd274a8c47",
			scalarHex: "4e615ec7cdd783db19b63db625b4bd8730f07b2d24fbe580dd3f43b3a3498502",
		}, {
			hashHex:   "d1d428aa3a8f014a4b2573a0af9240e18e3fe657e9a749",
			scalarHex: "22f8040569f976ed4533e451a5f8a00a82a336b182df2f3360e0b0ef1312100b",
		}, {
			hashHex:   "04c96cba68446468a13ba1d85477ffe3fbd6f3c88aafebe0f1d4e733",
			scalarHex: "7687b1e2f4c2bee2e7ecc348ab1cc63c4853f73c6078c0e543b7e2627436d304",
		}, {
			hashHex:   "94844f43438215fd44db27e015736f35816a0b655193de3befc17e0c807792",
			scalarHex: "c80d6f088df3f3625dddfc4c031a504e5a85227235e610a272aa7b310be1fa0c",
		}, {
			hashHex:   "3207c281f89913ec03d5b3b0b08810",
			scalarHex: "fa21358d2eb31fcc164cb4cf42ebbeeb79976472f36c3ce2ed9684b1b3677f06",
		}, {
			hashHex:   "75ef2c4e59a9206bb25e6e55be",
			scalarHex: "a2a06c06039c4afb6f7cefe48d6c4710b8ea17d12552b6dcf5d10e8c9efa0a0b",
		}, {
			hashHex:   "23168dcb92f68c065df88f3801beb87a",
			scalarHex: "002b05e0bc49ac56f3e120fafa3ce9b7620679ddc5e5e7c7ec48cf8dc21c0907",
		}, {
			hashHex:   "42721680880ef743a9e5258cf74c85232dfbdeb6283bf31d",
			scalarHex: "a8e2fad23f131b868b82cfca32ea1a1ab8b3516035b102abd94b599eed374e07",
		}, {
			hashHex:   "7a2a9d06b6ca081a9dcac3f9440c68",
			scalarHex: "98cd08928220afb6d2d5c2f703fa98f6a9c55e77f3fb6fd84dcdccbd4afbfe02",
		}, {
			hashHex:   "7b0cf6",
			scalarHex: "568c7d70cfe869dce2295a4208845eca5bf22de5bec3134ca5475c935e4f330b",
		}, {
			hashHex:   "0ea36e41326c1fae7e2cf716b4def1fbbe",
			scalarHex: "05309447b79be498ab58ac32d900d045acd01ec4391a153883f6c06106fbe90b",
		}, {
			hashHex:   "fa16119c2f0e557393e3256cb71eed9b5498758d353d891170020117b6ae88",
			scalarHex: "3e12a5c84834dd0bc2d74ace209aa26181171e46470907155e1a502942685a02",
		}, {
			hashHex:   "cac9bae2c66d6eda4093810836ef77852bd79c8064aa2ea29408ea85ac",
			scalarHex: "5c7ea9eb94ce6815900d389cca5b4eafbfc7ebd423b7b22cf15ffcab703f4c0e",
		}, {
			hashHex:   "815539bcbbbb3a582b3773e8",
			scalarHex: "4386a056d2a6d0daca73fda839c96d31ae2b26af8f9987f8297696e0fb5a6b00",
		}, {
			hashHex:   "6e",
			scalarHex: "68e36669be9590e654e62ee06f34a42791040ec42ef0aa69e59f09872f105c03",
		}, {
			hashHex:   "7d22ec3d1f3cea2be70b7bbfa09543aa",
			scalarHex: "6b89c0c7932271dcdad120e3d032a486629440c8dd28d7f72734fc7e11dab20c",
		}, {
			hashHex:   "4957c50e61573a7fc595041ffe8e1ee043a1d439263a5e115453fbf3",
			scalarHex: "797089272c0a29dc46cb0c3abdf7e8d709c6271127343d47dd17a8eec358cb08",
		}, {
			hashHex:   "c478f328ec84f1beb5b22bc5fd037e76422169ce8a",
			scalarHex: "79fccd7bae05990d2e7df119f79938549389a3ee2e0c346567a43e037ffb0d04",
		}, {
			hashHex:   "2bc6eca318d96652cadb2d211e98334704d01b77",
			scalarHex: "70024e07c87aa1d6e92056188518ae19255962c35af46f27602fcd15ea39160a",
		}, {
			hashHex:   "f8612a2e8a4fff879f1cbb0d310fe65b49107964",
			scalarHex: "12b2335e58eb20a8dc8ff1a5bb868d79edfd704bde1ae6d26a5fc601cae21209",
		}, {
			hashHex:   "39cee47a9ac8c924e9bd302746",
			scalarHex: "7c3ced52bd56302892bc2ffb2df2a19d8d05acf7dde7a3690f333cf672e3e604",
		}, {
			hashHex:   "21c2325f10d3c3337fdd3c4f8f6fe1",
			scalarHex: "9903500efba40172c75be826b20e2b1cf5111150bcd904fb4e1a557111205208",
		}, {
			hashHex:   "5d9fea",
			scalarHex: "497b515b746be9a6d4ee44d5cd39e326bbd5b14528c9a4383d124ed20442ca0d",
		}, {
			hashHex:   "a08629f1fca98eca85f5a6",
			scalarHex: "a66de38c9fbd42182b57c49d90cacdf5d8fa2cc762dd8d644fdf64f70d4d780c",
		}, {
			hashHex:   "bdfbb55fb1fc6f226c4bfa3466",
			scalarHex: "c5404c2b0d39db6fae4e3c3a8cb4e9085b4873834c094c1d65d75d89140f6309",
		}, {
			hashHex:   "929c1f648ee357a132597daa08a6b36c03d413a8956a1f11ba5d",
			scalarHex: "423e7dc43c18eb85f7e00652cb1ecaca5f41a454714e79f6c541ecb9a911d702",
		}, {
			hashHex:   "8fac9ad6c126f9421fd35e",
			scalarHex: "f5904cee95bb5e130f5ac77debe1676963b44ff0886a5e148717fb1d3a74e20c",
		}, {
			hashHex:   "458fcea5f4bf97a4cbb4f4396d9e97dde0",
			scalarHex: "cd9e96acc5184e429a9703d855d1dd3089cca3f62e80f1ed6e25574c080c4e07",
		}, {
			hashHex:   "d1dce32c02fcf1cabd244066b00e47992b9a6c31f4cec4",
			scalarHex: "15a800bcc57fe15b4af6e0ff9641511b92b4ed33478fd69dce61f7aa003eba01",
		}, {
			hashHex:   "a09aacfe861e94995a85998bb6f6c9d652112d8a77a1545e",
			scalarHex: "01f9835e4c61025dad60b7f15eb0a9fe4ee0fe54beeeed82a092a522b01c9d09",
		}, {
			hashHex:   "6ef2b70a5c57959b57a040b2a3528c56eafb1494ffe365f218131911",
			scalarHex: "0139a03b8763a4e01bb2886ce2ff095a6fde54719f59ee25a590687c85d4e60f",
		}, {
			hashHex:   "63e5f6a8b8588315e5a93daa883bebeecd67e9ec88c755",
			scalarHex: "04182129ec028b8ee4a1382c43479a45d27ffaa5ab90fa456dcb8b1540be3c09",
		}, {
			hashHex:   "1f44b7c7f1d0fbaad31dc2d984",
			scalarHex: "8b08c5a5209d106b8991cb5f1ee3c9a66367b669e7b1090a16309a7ed472790b",
		}, {
			hashHex:   "c3d88100ebc8f3ea2381e25d610d36fcc95d6fd542f54a5d03c6b3b52b",
			scalarHex: "b08038e00fc5e53a5f93f7691cea898c43064470c770bb202ed0fd9e72c0730c",
		}, {
			hashHex:   "8e21aa83f5128a6cd1a550161843727178d3b1ea0adb16d36d439b",
			scalarHex: "654923db734fc492cd2c28523dfc36860ab0c6f3dae018f762a886298f4aa205",
		}, {
			hashHex:   "fc7089fc0f72c700a3bee0819d83f87320e1c00967b75433cf1f6f",
			scalarHex: "fcd9337e5f5c6ac475d9a77836161b85d52be791ab80051b391ca62c1a625c09",
		}, {
			hashHex:   "ed76fd127c013952de4221994e10cd7141ba880893ec0b160900",
			scalarHex: "c1550e485843757565e1140010f2d4584ab475d4382c43b022b5d23ab9588b09",
		}, {
			hashHex:   "23",
			scalarHex: "a324bd0d2a8032141f682a88c5deb31892d86818ac98932f7ce2907c5976fb0e",
		}, {
			hashHex:   "ff2d9f9e7cc8e3514bf9ec20e5",
			scalarHex: "06ecc498146a9f3b93a674dcf8ba4ef7de33c9e940379891ddd8c1d825848305",
		}, {
			hashHex:   "599945d722a743e1",
			scalarHex: "0ad489bd8d81acecb2e655a252a02940672f93f145fb4dbb75740154f3863c0b",
		}, {
			hashHex:   "adad4c02a9a66205ce",
			scalarHex: "d7a985ab9f4b8b7a72d3b4c2f5de10bae0032fa4f6cf7e8ba28d58a53bebe207",
		}, {
			hashHex:   "d50d3594f4eaf29b93a3e2c212",
			scalarHex: "c8534126bff1ebf61c9287c798d1f9b8b867a670375ff3f11b712564e83ff008",
		}, {
			hashHex:   "0dd235b0323abbcb9996ae149c2e1abda8bfa185ebb2a64f53851887772021",
			scalarHex: "9b9f71b76ee7c39ea2641f0452b65f53538f47cabdc7fc4ae51b8f4b8c904105",
		}, {
			hashHex:   "997402",
			scalarHex: "a9d7d12d7fb12ba82f66d6b7e9aea507268e1f2bdfa26657c0e5dd1f6cc28c0d",
		}, {
			hashHex:   "53dc8152b03725b6f96f258376af0fc6e73f16daeaa2d19696f539c234",
			scalarHex: "3a5e74a06be26f674f337df96db52248b7205675dab1cc4595ded2e244cdeb00",
		}, {
			hashHex:   "2b4485a77085d16d1634afb46b68bed59d6590199c0f",
			scalarHex: "9d883b5140b45b8cb19b1e58ba197aefb82b19282bba839a3f449c4aa4d8bb03",
		}, {
			hashHex:   "cd39",
			scalarHex: "5d209f5ec13eccee9dd01c5276c6c3028eae3520b8f10f01cfdef216ae1b870b",
		}, {
			hashHex:   "13bfcabdc8b673b87493f669c79184bcd33f42",
			scalarHex: "ac00b11e079c70c9893562f707e647566a301eb175d93ebba9183747b29c7802",
		}, {
			hashHex:   "b68c5d50e28f93807d4e77a675f2bdcb3e81f75963d531dfed1101cb",
			scalarHex: "1a84edbaa00d14f2e6f243d0fdf328d0f2dcc6fd392e3da243b731a07133ff07",
		}, {
			hashHex:   "5c5623df5a43f56dba69f2fcfc5c704db2a121e1f4ecbaabda",
			scalarHex: "7a6bb3c84258eeebf96fdc3b5be8cc81e471b721a22de3b9091be248a7ba8204",
		}, {
			hashHex:   "9d8386f72297cf41427657bd19327fcacefa2b",
			scalarHex: "99aaac34b72fe19924765d084eaeeb14ca543b9857eda55e85a67bdf6edb400d",
		}, {
			hashHex:   "935f8cfe29912dd29070026db5ca0af64e4e34",
			scalarHex: "20fa6943ad7d79e8154b8eb7cd7911b33b0e4aea56e6d3ad05c8ea79bc763008",
		}, {
			hashHex:   "f4d62168478835caa51f5f",
			scalarHex: "6d69674b71c9ae54138178d439e3524dcb17864b5dea0272691a88beccd2530e",
		}, {
			hashHex:   "f5a4ee908a77ee51b8c3466899c575df40a814e56bbe4fed22",
			scalarHex: "e00a483dc31ec7098b48850d0e88bd15693e27ce422809f49e6f9c5463eb7106",
		}, {
			hashHex:   "246ac597c8386b252b8037a8e7f11f4acd02c3f8bb7351",
			scalarHex: "c7c2ad02ccd91b2434abe439942ce4dcc5dfd44ccf8f7ae99994229c876ee403",
		}, {
			hashHex:   "8122f1ab97f113cbcd034caf",
			scalarHex: "8eb6dfbd5c7d62cf10502f2ef4e90dcf49e89e374f9486ec139fca588d1cdb02",
		}, {
			hashHex:   "3b64403dc86b0f37",
			scalarHex: "6f89f29aef14824c944d44870dbc17372f6a5e9f194e4e9b2f0982f35493c107",
		}, {
			hashHex:   "0e8da976e3aaf59ebdc09e9582292abd7d9dcdf90c83d102314626aa2cf2d9",
			scalarHex: "79707beedaaa1d231d0d61eec3c935454b542746ef8b5776c877ea6b482d3703",
		}, {
			hashHex:   "a217d6214ac5a6ea6b35a46ec07dd772cf0dd741bc58892a44e1be",
			scalarHex: "4a3a57496112178056c6d749e86d06917384433edc8a7cecf6587ad0e9fc0703",
		}, {
			hashHex:   "25a7298b03157dff98428fd7201b",
			scalarHex: "ffc577f71d6e7d18727d43abe19fbaabbd1ee3b953b2b4c1be014db173f34704",
		}, {
			hashHex:   "fe46a74c7e7c",
			scalarHex: "384a6c160527e298885f914c16331c3007a6859d95ddc3d699cc7aea15459007",
		}, {
			hashHex:   "fb0eef56ce078311e4dd0afa08b57d4f497eab4beb35c8c74fc667959249d3",
			scalarHex: "790b735b5bdbee8fa44b6f07513f6e81eeb2f3d62f6fdd237a628d079efb250a",
		}, {
			hashHex:   "5398f0b78de8fbab02402732677840c21a0cfde4d0bdd1aad8976ee713",
			scalarHex: "804ef61908aa15bf5e8aeb97c019df5794993a4f2e2ada967b22ebc32f17470b",
		}, {
			hashHex:   "07758dc6ae54e8cc704d288046",
			scalarHex: "80ea68b156b6c9931b63f63afe79c97642c4e9c1cd2dde723cea3a266b8fc40b",
		}, {
			hashHex:   "18877a7e05b84ec7c1fdc744dad76700b95c808d0a82123d92963a3471",
			scalarHex: "94f2b511f50779bab1c105d15a2a0af058d6a45d879107930a6aa5b0c8d1fa0b",
		}, {
			hashHex:   "2f37fac2f6bd42",
			scalarHex: "054b5a4762a7482c4923cd5efcaffbe3d4feec20fec4fb830c917626e9806005",
		}, {
			hashHex:   "ea753ba82b4573d428d526de89daccdfa7a33079aa9c9ac3",
			scalarHex: "d9bf5688fed9c3f4a9de4c001f1de130002f117bd8543350d57b8ef380b76b06",
		}, {
			hashHex:   "2a5d772c76aae0040915ffd7",
			scalarHex: "8227a0904298e726cedb75746b0a3b41662002b4ed8fa05c2110e4a15bfd310c",
		}, {
			hashHex:   "585900d92342cb8448c944f97d1642",
			scalarHex: "acfa0d43b9c6a91810b0fa1bd42f0d9e077f7f5a62f9d9aaff8418e1130ea508",
		}, {
			hashHex:   "2ace",
			scalarHex: "427f5090283713a2a8448285f2a22cc8cf5374845766b6370425e2319e40f50d",
		},
	}
	for _, test := range tests {
		toHash, _ := hex.DecodeString(test.hashHex)
		want := HexToBytes(test.scalarHex)
		got := HashToScalar(toHash)
		if want != got {
			t.Errorf("%x, want %x, got %x", toHash, want, got)
		}
	}
}

func TestHashToEC(t *testing.T) {
	tests := []struct {
		pubkeyHex   string
		extendedHex string
	}{
		{
			pubkeyHex:   "da66e9ba613919dec28ef367a125bb310d6d83fb9052e71034164b6dc4f392d0",
			extendedHex: "52b3f38753b4e13b74624862e253072cf12f745d43fcfafbe8c217701a6e5875",
		},
		{
			pubkeyHex:   "a7fbdeeccb597c2d5fdaf2ea2e10cbfcd26b5740903e7f6d46bcbf9a90384fc6",
			extendedHex: "f055ba2d0d9828ce2e203d9896bfda494d7830e7e3a27fa27d5eaa825a79a19c",
		},
		{
			pubkeyHex:   "ed6e6579368caba2cc4851672972e949c0ee586fee4d6d6a9476d4a908f64070",
			extendedHex: "da3ceda9a2ef6316bf9272566e6dffd785ac71f57855c0202f422bbb86af4ec0",
		},
		{
			pubkeyHex:   "9ae78e5620f1c4e6b29d03da006869465b3b16dae87ab0a51f4e1b74bc8aa48b",
			extendedHex: "72d8720da66f797f55fbb7fa538af0b4a4f5930c8289c991472c37dc5ec16853",
		},
		{
			pubkeyHex:   "ab49eb4834d24db7f479753217b763f70604ecb79ed37e6c788528720f424e5b",
			extendedHex: "45914ba926a1a22c8146459c7f050a51ef5f560f5b74bae436b93a379866e6b8",
		},
		{
			pubkeyHex:   "5b79158ef2341180b8327b976efddbf364620b7e88d2e0707fa56f3b902c34b3",
			extendedHex: "eac991dcbba39cb3bd166906ab48e2c3c3f4cd289a05e1c188486d348ede7c2e",
		},
		{
			pubkeyHex:   "f21daa7896c81d3a7a2e9df721035d3c3902fe546c9d739d0c334ed894fb1d21",
			extendedHex: "a6bedc5ffcc867d0c13a88a03360c8c83a9e4ddf339851bd3768c53a124378ec",
		},
		{
			pubkeyHex:   "3dae79aaca1abe6aecea7b0d38646c6b013d40053c7cdde2bed094497d925d2b",
			extendedHex: "1a442546a35860a4ab697a36b158ded8e001bbfe20aef1c63e2840e87485c613",
		},
		{
			pubkeyHex:   "3d219463a55c24ac6f55706a6e46ade3fcd1edc87bade7b967129372036aca63",
			extendedHex: "b252922ab64e32968735b8ade861445aa8dc02b763bd249bff121d10829f7c52",
		},
		{
			pubkeyHex:   "bc5db69aced2b3197398eaf7cf60fd782379874b5ca27cb21bd23692c3c885cc",
			extendedHex: "ae072a43f78a0f29dc9822ae5e70865bbd151236a6d7fe4ae3e8f8961e19b0e5",
		},
		{
			pubkeyHex:   "98a6ed760b225976f8ada0579540e35da643089656695b5d0b8c7265a37e2342",
			extendedHex: "6a99dbfa8ead6228910498cc3ff3fb18cb8627c5735e4b8657da846c16d2dcad",
		},
		{
			pubkeyHex:   "e9cdc9fd9425a4a2389a5d60f76a2d839f0afbf66330f079a88fe23d73eae930",
			extendedHex: "8aa518d091928668f3ca40e71e14b2698f6cae097b8120d7f6ae9afba8fd3d60",
		},
		{
			pubkeyHex:   "a50c026c0af2f9f9884c2e9b8464724ac83bef546fec2c86b7de0880980d24fb",
			extendedHex: "b07433f8df39da2453a1e13fd413123a158feae602d822b724d42ef6c8e443bf",
		},
		{
			pubkeyHex:   "bf180e20d160fa23ccfa6993febe22b920160efc5a9614245f1a3a360076e87a",
			extendedHex: "9d6454ff69779ce978ea5fb3be88576dc8feaedf151e93b70065f92505f2e800",
		},
		{
			pubkeyHex:   "b2b64dfeb1d58c6afbf5a56d8c0c42012175ebb4b7df30f26a67b66be8c34614",
			extendedHex: "0523b22e7f220c939b604a15780abc5816709b91b81d9ee1541d44bd2586bbd8",
		},
		{
			pubkeyHex:   "463fc877f4279740020d10652c950f088ebdebeae34aa7a366c92c9c8773f63a",
			extendedHex: "daa5fa72e70c4d3af407b8f2f3364708029b2d4863bbdde54bd67bd08db0fcad",
		},
		{
			pubkeyHex:   "721842f3809982e7b96a806ae1f162d98ae6911d476307ad1e4f24522fd26f55",
			extendedHex: "4397c300a8cfcb42e7cc310bc975dc975ec2d191eaa7e0462998eb2830c34126",
		},
		{
			pubkeyHex:   "384da8d9b83972af8cbefc2da5efc744037c8ef40efa4b3bacc3238a6232963d",
			extendedHex: "3c80f107e6868f73ef600ab9229a3f4bbe24f4adce52e6ab3a66d5d510e0670d",
		},
		{
			pubkeyHex:   "e26f8adef5b6fe5bb01466bff0455ca23fda07e200133697b3b6430ca3332bde",
			extendedHex: "e262a58bcc1f8baf1980e00d5d40ba00803690174d14fb4c0f608429ce3df773",
		},
		{
			pubkeyHex:   "6e275b4ea4f085a5d3151aa08cf16a8c60b078e70be7ce5dac75b5d7b0eebe7c",
			extendedHex: "cb21b5a7744b4fcdc92ead4be0b04bcb9145e7bb4b06eff3bb2f0fe429b85108",
		},
		{
			pubkeyHex:   "a0dde4561ad9daa796d9cd8a3c34fd41687cee76d128bf2e2252466e3ef3b068",
			extendedHex: "79a2eb06bb7647f5d0aae5da7cf2e2b2d2ce890f25f2b1f81bfc5fef8c87a7d3",
		},
		{
			pubkeyHex:   "dbaf63830e037b4c329969d1d85e58cb6c4f56014fd08eb38219bd20031ae27c",
			extendedHex: "079c93ae27cd98075a487fd3f7457ad2fb57cdf12ec8651fedd944d765d07549",
		},
		{
			pubkeyHex:   "1e87ba8a9acf96948bc199ae55c83ab3277be152c6d0b1d68a07955768d81171",
			extendedHex: "5c6339f834116791f9ea22fcc3970346aaeddacf13fbd0a7d4005fbd469492ca",
		},
		{
			pubkeyHex:   "5a544088e63ddf5b9f444ed75a75bc9315c4c50439522f06b4823ecaf5e8a08d",
			extendedHex: "e95ca0730d57c6469be3a0f3c94382f8490257e2e546de86c650bdbc6482eaee",
		},
		{
			pubkeyHex:   "e4e06d92ebb036a5e4bb547dbaa43fd70db3929eef2702649455c86d7e59aa46",
			extendedHex: "e26210ff8ee28e24ef2613df40aa8a874b5e3c1d07ae14acc59220615aa334dc",
		},
		{
			pubkeyHex:   "5793b8b32dcc0f204501647f2976493c4f8f1fa5132315226f99f29a5a6fdfce",
			extendedHex: "656e390086906d99852c9696e831f62cb56fc8f85f9a5c936c327f23c7faf4fe",
		},
		{
			pubkeyHex:   "84f56fa4d7f12e0efd48b1f7c81c15d6e3843ebb419f4a27ec97028d4f9da19e",
			extendedHex: "0cbd4f0cd288e1e071cce800877de6aef97b63fff867424a4f2b2bab25602608",
		},
		{
			pubkeyHex:   "242683ddf0a9fc55f6585de3aa64ea17c9c544896ff7677cd82c98f833bdf2ca",
			extendedHex: "38c36d52314549213df7c7201ab7749a4724cbea92812f583bb48cabc20816ad",
		},
		{
			pubkeyHex:   "a93ee320dc030aa382168c2eb6d75fce6e5a63a81f15632d514c6de8a7cfa5ee",
			extendedHex: "bd0a2facaa95bc95215a94be21996e46f789ee8beb38e75a1173b75fc686c505",
		},
		{
			pubkeyHex:   "e36136601d84475d25c3f14efe030363d646658937a8a8a19a812d5e6deb5944",
			extendedHex: "2fb93d78fae299c9f6b22346acfb829796ee7a47ec71db5456d8201bec6c35a3",
		},
		{
			pubkeyHex:   "ba4b67d3d387c66baa4a32ec8b1db7681087e85076e71bab10036388c3aeb011",
			extendedHex: "cc01329ce56f963bf444a124751c45b2c779ccb6dea16ca05251baca246b5401",
		},
		{
			pubkeyHex:   "3fbc91896a2585154d6f7094c5ab9c487e29a27951c226eec1235f618e44946b",
			extendedHex: "7d983acbb901bf5497d0708392e5e742ec8c8036cbb0d03403e9929da8cc85a7",
		},
		{
			pubkeyHex:   "a2da289fed650e9901f69a5f33535eb47c6bd07798633cbf6c00ce3172df76ac",
			extendedHex: "dca8a4d30ec2d657fefd0dba9c1c5fd45a79f665048b3cf72ac2c3b7363da1ac",
		},
		{
			pubkeyHex:   "99025d2d493f768e273ed66cacd3a5b392761e6bd158ca09c8fba84631ea1534",
			extendedHex: "7ef5af79ab155ab7e1770a47fcd7f194aca43d79ec6e303c7ce18c6a20279b04",
		},
		{
			pubkeyHex:   "3cf1d01d0b70fb31f2a2f979c1bae812381430f474247d0b018167f2a2cd9a9f",
			extendedHex: "7c53d799ec938a21bb305a6b5ca0a7a355fa9a68b01d289c4f22b36ce3738f95",
		},
		{
			pubkeyHex:   "639c421b49636b2a1f8416c5d6e64425fe51e3b52584c265502379189895668e",
			extendedHex: "0b47216ae5e6e03667143a6cf8894d9d73e3152c64fb455631d81a424410e871",
		},
		{
			pubkeyHex:   "4ccf2c973348b7cc4b14f846f9bfcdcb959b7429accf6dede96248946841d990",
			extendedHex: "7fd41f5b97ba42ed03947dd953f8e69770c92cc34b16236edad7ab3c78cbbb2e",
		},
		{
			pubkeyHex:   "f76ae09fff537f8919fd1a43ff9b8922b6a77e9e30791c82cf2c4b8acb51363e",
			extendedHex: "8e2c6bf86461ad2c230c496ee3896da33c11cc020fd4c70faa3645b329049234",
		},
		{
			pubkeyHex:   "98932da7450f15db6c1eef78359904915c31c2aa7572366ec8855180edb81e3a",
			extendedHex: "86180adddfac0b4d1fb41d58e98445dde1da605b380d392e9386bd445f1d821c",
		},
		{
			pubkeyHex:   "ab26a1660988ec7aba91fc01f7aa9a157bbc12927f5b197062b922a5c0c7f8dd",
			extendedHex: "2c44a43eda0d0aad055f18333e761f2f2ec11c585ec7339081c19266af918e4f",
		},
		{
			pubkeyHex:   "4465d0c1b4930cc718252efd87d11d04162d2a321b9b850c4a19a6acdfca24f4",
			extendedHex: "b03806287d804188a4d679a0ecee66f399d7bdc3bd1494f9b2b0772bbb5a034f",
		},
		{
			pubkeyHex:   "0f2a7867864ed00e5c40082df0a0b031c89fa5f978d9beb2fde75153f51cfb75",
			extendedHex: "5c471e1b118ef9d76c93aec70e0578f46e8db1d55affd447c1f64c0ad9a5caa5",
		},
		{
			pubkeyHex:   "5c2808c07d8175f332cae050ce13bec4254870d76abff68faf34b0b8d3ad5000",
			extendedHex: "eeff1d9a5aa428b7aecc575e63dde17294072eb246568493e1ed88ce5c95b779",
		},
		{
			pubkeyHex:   "36300a21601fad00d00da45e27b36c11923b857f97e50303bd01f21998eaef95",
			extendedHex: "b33b077871e6f5dad8ff6bc621c1b6dedcf700777d996c8c02d73f7297108b7e",
		},
		{
			pubkeyHex:   "9e1afb76d6c480816d2cedd7f2ab08a36c309efaa3764dcdb51bad6049683805",
			extendedHex: "4cd96ba7b543b1a224b8670bf20b3733e3910711d32456d3e58e920215788adf",
		},
		{
			pubkeyHex:   "685f152704664495459b76c81567a4b571e8b307dd0e3c9b08ee95651a006047",
			extendedHex: "80dd6b637580cb3be76025867f1525852b65a7a66066993fda3af7eb187dc1a5",
		},
		{
			pubkeyHex:   "0b216444391a1163c14f7b27f9135e9747978c0e426dce1fa65c657f3e9146be",
			extendedHex: "021259695a6854a4a03e8c74d09ab9630a401bfca06172a733fe122f01af90b4",
		},
		{
			pubkeyHex:   "cfcb35e98f71226c3558eaa9cf620db5ae207ece081ab13ddea4b1f122850a5a",
			extendedHex: "46763d2742e2cdffe80bb3d056f4d3a1565aa83f19aab0a1f89e54ad81ae0814",
		},
		{
			pubkeyHex:   "07e7292da8cdcdb58ee30c3fa16f1d609e9b3b1110dd6fa9b2cc18f4103a1c12",
			extendedHex: "fe949ca251ac66f13a8925ae624a09cdbf6696d3c110442338d37700536e8ec7",
		},
		{
			pubkeyHex:   "813bc7e3749e658190cf2a4e358bc07a6671f262e2c4eef9f44c66066a72e6a7",
			extendedHex: "6b92fbda984bd0e6f4af7a5e04c2b66b6f0f9d197a9694362a8556e5b7439f8a",
		},
		{
			pubkeyHex:   "89c50a1e5497156e0fae20d99f5e33e330362b962c9ca00eaf084fe91aaec71d",
			extendedHex: "ef36cb75eb95fb761a8fa8c376e9c4447bcd61421250f7a711bd289e6ed78a9b",
		},
		{
			pubkeyHex:   "d9bd9ff2dd807eb25de7c5de865dbc43cce2466389cedbc92b90aab0eb014f81",
			extendedHex: "30104771ff961cd1861cd053689feab888c57b8a4a2e3989646ea7dea40f3c04",
		},
		{
			pubkeyHex:   "b8c837501b6ca3e118db9848717c847c062bf0ebeca5a7c211726c1426878af5",
			extendedHex: "19a1e204b4a32ce9cccf5d96a541eb76a78789dceaf4fe69964e58ff96c29b63",
		},
		{
			pubkeyHex:   "84376c5350a42c07ac9f96e8d5c35a8c7f62c639a1834b09e4331b5962ecace8",
			extendedHex: "ba1e4437d5048bd1294eadc502092eafc470b99fde82649e84a52225e68e88f2",
		},
		{
			pubkeyHex:   "a3345e4a4cfc369bf0e7d11f49aed0d2a6ded00e3ff8c7605db9a919cf730640",
			extendedHex: "0d318705c16e943c0fdcde134aaf6e4ccce9f3d9161d001861656fc7ea77a0b1",
		},
		{
			pubkeyHex:   "3c994dfb9c71e4f401e65fd552dc9f49885f88b8b3588e24e1d2e9b8870ffab1",
			extendedHex: "984157de5d7c2c4b43b2bffea171809165d7bb442baea88e83b27f839ebdb939",
		},
		{
			pubkeyHex:   "153674c1c1b18a646f564af77c5bd7de452dc3f3e1e2326bfe9c57745b69ec5c",
			extendedHex: "e9a4a1e225ae472d1b3168c99f8ba1943ad2ed84ef29598f3f96314f22db9ef2",
		},
		{
			pubkeyHex:   "2d46a705d4fe5d8b5a1f4e9ef46d9e06467450eb357b6d39faa000995314e871",
			extendedHex: "b9d1aec540bf6a9c0e1b325ab87d4fbe66b1df48986dde3cb62e66e136eba107",
		},
		{
			pubkeyHex:   "6764c3767f16ec8faecc62f9f76735f76b11d7556aeb61066aeaeaad4fc9042f",
			extendedHex: "3a5c68fb94b023488fb5940e07d1005e7c18328e7a84f673ccd536c07560a57b",
		},
		{
			pubkeyHex:   "c99c6ee5804d4b13a445bc03eaa07a6ef5bcb2fff0f71678dd3bd66b822f8be8",
			extendedHex: "a9e1ce91deed4136e6e53e143d1c0af106abde9d77c066c78ebbf5d227f9dde0",
		},
		{
			pubkeyHex:   "3009182e1efac085c7eba24a7d9ef28ace98ebafa72211e73a41c935c37e6768",
			extendedHex: "e55431a4c89d38bd95f8092cdf6e44d164ad5855677aba17ec262abc8c217c86",
		},
		{
			pubkeyHex:   "e7153acd114a7636a207be0b67fa86fee56dd318f2808a81e35dd13d4251b2d0",
			extendedHex: "ff2b98d257e4d4ff7379e8871441ca7d26e73f78f3f5afcf421d78c9799ba677",
		},
		{
			pubkeyHex:   "6378586744b721c5003976e3e18351c49cd28154c821bc45338892e5efedd197",
			extendedHex: "3d765fb7bb4e165a3fa6ea00b5b5e22250f3861f0db0099626d9a9020443dda2",
		},
		{
			pubkeyHex:   "5be49aba389b7e3ad6def3ba3c7dbec0a11a3c36fc9d441130ef370b8a8d29c2",
			extendedHex: "2d61faf38062dc98ae1aaafec05e90a925c9769df5b8b8f7090d9e91b2a11151",
		},
		{
			pubkeyHex:   "f7bc382178d38e1b9a1a995bd8347c1283d8a2e8d150379faa53fd125e903d2b",
			extendedHex: "544c815da65c3c5994b0ac7d6455578d03a2bc7cf558b788bcdb3430e231635a",
		},
		{
			pubkeyHex:   "c28b5c4b6662eebb3ec358600644849ebeb59d827ed589c161d900ca18715fa8",
			extendedHex: "a2d64db3c0e0353c257aadf9abc12ac779654d364f348b9f8e429aa7571203db",
		},
		{
			pubkeyHex:   "3a4792e5df9b2416a785739b9cf4e0d68aef600fa756a399cc949dd1fff5033a",
			extendedHex: "4b54591bd79c30640b700dfb7f20158f692f467b6af70bd8a4e739c14a66c86a",
		},
		{
			pubkeyHex:   "002e70f25e1ceaf35cc14b2c6975a4c777b284a695550541e6f5424b962c19f5",
			extendedHex: "73987e9342e338eb57a7a9e03bd33144db37c1091e952a10bd243c5bb295c18a",
		},
		{
			pubkeyHex:   "7eb671319f212c9cae0975571b6af109124724ba182937a9066546c92bdeff0c",
			extendedHex: "49b46da3be0df1d141d2a323d5af82202afa2947a95b9f3df47722337f0d5798",
		},
		{
			pubkeyHex:   "ca093712559c8edd5c51689e2ddcb8641c2960e5d9c8b03a44926bb798a0c8dc",
			extendedHex: "b9ef9cf0f8e4a3d123db565afafb1102338bfb75498444ac0a25c5ed70d615da",
		},
		{
			pubkeyHex:   "cfea0a08a72777ff3aa7be0d8934587fa4127cd49a1a938232815dc3fd8b23ac",
			extendedHex: "b4de604b3d712f1ef578195fb0e53c865d41e2dfe425202c6cfe6f10e4404eb5",
		},
		{
			pubkeyHex:   "aa0122ae258d6db21a26a31c0c92d8a0e3fdb46594aed41d561e069687dedcd6",
			extendedHex: "5247eaec346de1c6cddf0ab04c12cd1d85cdb6d3a2fba2a5f9a5fe461abef5eb",
		},
		{
			pubkeyHex:   "b3941734f4d3ba34ccaf03c4c737ac5a1e036eb74309300ce44d73aca24fef08",
			extendedHex: "535938985c936e3780c61fe29a4121d6cb89a05080b6c2147031ea0c2b5b9829",
		},
		{
			pubkeyHex:   "8c2ee1041a2743b30dcbf413cc9232099b9268f82a5a21a09b63e7aff750882f",
			extendedHex: "6ad0d4b3a65b522dfad0e9ac814b1fb939bc4910bd780943c72f57f362754cca",
		},
		{
			pubkeyHex:   "4b6829a2a2d46c8f0d0c23db0f735fcf976524bf39ccb623b919dd3b28ad5193",
			extendedHex: "2e0097d7f92993bc45ba06baf4ca63d64899d86760adc4eb5eeefb4a78561050",
		},
		{
			pubkeyHex:   "9c1407cb6bba11e7b4c1d274d772f074f410d6fe9a1ee7a22cddf379257877d9",
			extendedHex: "692261c7d6a9a7031c67d033f6d82a68ef3c27bd51a5666e55972238769821cd",
		},
		{
			pubkeyHex:   "638c42e4997abf8a4a9bffd040e31bd695d590cde8afbd7efd16ffdbae63bf66",
			extendedHex: "793024c8ce196a2419f761dde8734734af6bd9eb772b30cc78f2cb89598dce97",
		},
		{
			pubkeyHex:   "1fb60d79600de151a1cf8a2334deb5828632cbd91cb5b3d45ae06e08187ae23d",
			extendedHex: "ff2542cde5bc2562e69471a31cfc3d0c26e2f6ccc1891a633b07a3968e42521c",
		},
		{
			pubkeyHex:   "d2fdbbae4e38a1b734151c3df52540feb2d3ff74edfef2f740e49a5c363406ee",
			extendedHex: "344c83ba6ff4e38b257077623d298d2f2b52002645021241bc9389f81b29ad12",
		},
		{
			pubkeyHex:   "836c27a6ddfe1a24aba3d6022dff6dfe970f142d8b4ac6afb8efcba5a051942f",
			extendedHex: "b8af481d33726b3f875268282d621e4c63f891a09f920b8f2f49080f3a507387",
		},
		{
			pubkeyHex:   "46281153ddcdf2e79d459693b6fe318c1969538dd59a750b790bfff6e9481abf",
			extendedHex: "8eaf534919ab6573ba4e0fbde0e370ae01eae0763335177aa429f61c4295e9d4",
		},
		{
			pubkeyHex:   "d57b789e050bf3db462b79a997dac76aa048d4be05f133c66edee56afd3dbe66",
			extendedHex: "0c5a294cb2cbb6d9d1c0a1d57d938278f674867f612ed89dcbe4533449f1a131",
		},
		{
			pubkeyHex:   "548d524d03ac22da18ff4201ce8dbee83ad9af54ee4e26791d26ed2ab8f9bfc7",
			extendedHex: "c6609d9e7d9fd982dec8a166ff4fb6f7d195b413aad2df85f73d555349134f3b",
		},
		{
			pubkeyHex:   "cc920690422e307357f573b87a6e0e65f432c6ec12a604eb718b66ba18897a56",
			extendedHex: "6f11c466d1c72fccd81e51d9bda03b6e8d6a395e1d931b2a84e392dc9a3efa18",
		},
		{
			pubkeyHex:   "c7fb8a51f5fcd8824fc0875d4eb57ab4917cb97090a6e2288f852f2bb449edd9",
			extendedHex: "45543fea6eed461016e48598b521f18ff70178afea18032b188deea3e56052fc",
		},
		{
			pubkeyHex:   "c681bb1b829e24b1c52cb890036b89f0029d261c6a15e5b2c684ee7dfe91e746",
			extendedHex: "263006fe2c6b08f1ab29cdf442472c298e2faf225bbf5c32399d3745cd3904bd",
		},
		{
			pubkeyHex:   "e06411c542312fdd305e17e46be14c63bab5836dc8751da06164b1ae22d4e20f",
			extendedHex: "901871be7a7ff5aecade2acff869846f3c50de69307ac155f2aa3a74d5472ef2",
		},
		{
			pubkeyHex:   "9c725a2acb80fa712f9781da510e5163b1b30f4e1c064c26b5185e537f0614ea",
			extendedHex: "02420d49257846eb39fddd196d3171679f6be21d9adac667786b65a6e90f57b1",
		},
		{
			pubkeyHex:   "22792772820feafa85c5cb3fa8f876105251bef08617d389619697f47dff54f2",
			extendedHex: "a3ad444e7811693687f3925e7c315ae55d08d9f4b0a29876bc2a891ab941c1c3",
		},
		{
			pubkeyHex:   "0587b790121395d0f4f39093d10b4817f58a1e80621a24eea22b3c127d6ac5a2",
			extendedHex: "86c417c695c64c7becaad0d59ddbb2bca4cb2b409a21253d680aac1a08617095",
		},
		{
			pubkeyHex:   "fa0b5f28399bef0cd87bfe6b8a2b69e9c5506fb4bacd22deba8049615a5db526",
			extendedHex: "ede0ea240036ff75d075258a053f3ce5d6f77925d358dbe33c06509fc9b12111",
		},
		{
			pubkeyHex:   "62a3274fc0bed109d5057b865c2ba6b6a5a417cb90a3425674102fcd457ede2d",
			extendedHex: "ff7e46751bb4dcd1e800a8feab7cf6771f42dc0cfed7084c23b8a5d255a6f34e",
		},
		{
			pubkeyHex:   "a6fcd4aecaaaf281563b9b7cd6fbc7b1829654f644f4165942669a2ef632b2bf",
			extendedHex: "28f136be0eb957a5b36f8ec294399c9f73ad3a3c9bb953ad191758ced554a233",
		},
		{
			pubkeyHex:   "01baa4c06d6676c9b286cda76ed949fd80a408b3309500ba84a5bb7e3dce58e2",
			extendedHex: "a943d1afa2efce284740e7db21ea02db70b124808be2ff80cbf9b9cb96c7b73e",
		},
		{
			pubkeyHex:   "dd9aff9c006ba514cef8fae665657bc9813fe2715467cf479643ea4c4e365d6d",
			extendedHex: "68de2f7d49de4004286ce0989a06a686b15d0f463a02ffd448a18914e1ddf713",
		},
		{
			pubkeyHex:   "3df3513d5e539161761ce7992ab9935f649bc934bed0da3c5e1095344b733bb9",
			extendedHex: "e9c2dd747d7b2482474325943cd850102b8093164678362c7621993a790e2a8a",
		},
		{
			pubkeyHex:   "7680cfb244dc8ef37c671fff176be1a3dad00e5d283f93145d0cbee74cca2df4",
			extendedHex: "a0fd8c3cca16a130eaa5864cbe8152b7adfbf09e8cf72244b2fc8364c3b20bf4",
		},
		{
			pubkeyHex:   "8a547c38bd6b219ea0d612d4a155eba9c56034a1405dcf4b608de787f37e0fd8",
			extendedHex: "76bf0dc40fd0a5508c5e091d8bb7eccfa28b331e72c6a0d4ac0e05a3d651850b",
		},
		{
			pubkeyHex:   "dd93901621f58465e9791012afa76908f1e80ad80e52b809dc7fc32bb004f0a8",
			extendedHex: "09a0b7ecfe8058b1e9ee01c9b523826867ca97a32efad29ac8ceebca67a4ea00",
		},
		{
			pubkeyHex:   "b643010220f1f4ee6c7565f6e1b3dc84c18274ede363ac36b6af3707e69a1542",
			extendedHex: "233c9ff8de59e5f96c2f91892a71d9d93fa7316319f30d1615f10ac1e01f9285",
		},
		{
			pubkeyHex:   "c2637b2299dfc1fd7e953e39a582bafd19e6e7fff3642978eb092b900dbfea80",
			extendedHex: "339587ba1c05e2cba44196a4be1fd218b772199e2c61c3c0ff21dcd54b570c43",
		},
		{
			pubkeyHex:   "1f36d3a7e7c468eb000937de138809e381ad2e23414cbbaac49b7f33533ed486",
			extendedHex: "7e5b0a96051c77237a027a79764c2763487af88121c7774645e97827fb744888",
		},
		{
			pubkeyHex:   "8c142a55f60b2edbe03335b7f90aa2bd63e567048a65d61c70cb28779c5200af",
			extendedHex: "d3d6d5563b3d81c8c91cf9806bb13b2850fb7c162c610fd2f5b83c464add8182",
		},
		{
			pubkeyHex:   "99e7b98293c9de1f81aff1376485a990014b8b176521b2a68cdbde6300190398",
			extendedHex: "119cbc01a1d9b9fb4759031d3a70685aebea0f01bc5ee082ce824265fd21b3b4",
		},
		{
			pubkeyHex:   "9753bd38be072b51490290be6207ca4545e3541bdf194e0850ae0a9f9e64b8ba",
			extendedHex: "1ad3aa759863153606fa6570f0e1290baded4c8c1f2ba0f67c1911bfc8ccd7a0",
		},
		{
			pubkeyHex:   "322703864ceee19b7f17cec2a822f310f0c4da3ff98b0be61a6fd30ac4db649c",
			extendedHex: "89d9e7a5947e1cde874e4030de278070aae363063cd3592ce5411821474f0816",
		},
		{
			pubkeyHex:   "c1acd01e1e535fad273a8b757d981470f43dd7d95af732901fbba16b6e245761",
			extendedHex: "57e80445248111150da5e63c706b4abbf3eef2cc508bd0347ff6b81e8c59f5bc",
		},
		{
			pubkeyHex:   "492473559f181bbe78f60215bc6d3a5168435ea2fc0a508372d6f5ca126e9767",
			extendedHex: "df3965f137cf6f60c56ebd7c8f246281fd6dc92ce23a37e9f846f8452c884e01",
		},
		{
			pubkeyHex:   "afa9d6e0e2fb972ee806beb450c2c0165e58234b0676a4ec0ca19b6e710d7c35",
			extendedHex: "669a57e69dd2845a5e50ed8e5d8423ac9ae792a43c7738554d6c5e765a7b088a",
		},
		{
			pubkeyHex:   "094de050bdadef3b7dbaeeca29381c667e63e71220970149d97b95db8f4db61b",
			extendedHex: "0cf5d03530c5e97850d0964c6a394de9cde1e8e498f8c0e173c518242c07f99a",
		},
		{
			pubkeyHex:   "2ce583724bc699ad800b33176a1d983512fe3cb3afa65d99224b23dae223efb7",
			extendedHex: "e1548fd563c75ae5b5366dbab4cb73c54e7d5e087c9e5453125ff8fbe6c83a5c",
		},
		{
			pubkeyHex:   "8064974b976ff5ef6adaade6196ab69cda6970cd74f7f5899181805f691ad970",
			extendedHex: "98ae63c47331a4ac433cb2f17230c525982d89d21e2838515a36ec5744ec2d15",
		},
		{
			pubkeyHex:   "384911047de609c6ae8438c745897357989363885cef2381a8a00a090cf04a58",
			extendedHex: "4692ec3a0a03263620841c108538d584322fdd24d221a74bf1e1f407f83828af",
		},
		{
			pubkeyHex:   "0e1b1ced5ae997ef9c10b72cfc6d8c36d7433c01fc04f4083447f87243282528",
			extendedHex: "6ee443ab0637702b7340bd4a908b9e2e63df0cc423c409fb320eb3f383118b80",
		},
		{
			pubkeyHex:   "5a7aea70c85c040af6ff3384bcaa63ec45c015b55b44fffa37ab982a00dc57c5",
			extendedHex: "2df2e20137cefd166c767646ecd2e386d28f405aebe43d739aa55beba04ed407",
		},
		{
			pubkeyHex:   "3e878a3567487f20f7c98ea0488a40b87f1ba99e50bbfe9f00a423f927cbd898",
			extendedHex: "697c7e60e4bf8c429ba7ac22b11a4b248d7465fc6abe597ec6d1e1c973330688",
		},
		{
			pubkeyHex:   "c0bb08350d8a4bb6bf8745f6440e9bd254653102a81c79d6528da2810da758e4",
			extendedHex: "396a872ac9147a69b27223bf4ec4198345b26576b3690f233b832395f2598235",
		},
		{
			pubkeyHex:   "6c3026a9284053a4ddb754818f9ae306ffa96eb7003bd03826eeccc9a0cf656e",
			extendedHex: "bef73da51d3ba9972a33d1afb7d263094b66ab6dbe3988161b08c17f8c69c2d5",
		},
		{
			pubkeyHex:   "f80b7d8f5a80d321af3a42130db199d9edcb8f5a82507d8bfca6d002d65458b6",
			extendedHex: "aa59c167ea60ee024421bfbd00adbb3cbfc20e16bd3c9b172a6bef4d47ca7f57",
		},
		{
			pubkeyHex:   "bc0ffc24615aa02fafef447f17e7b776489cd2cc909f71e8344e01cad9f1610d",
			extendedHex: "5c4195cc8dc3518143f06a9c228ae59ec9a6425a8fab89bfc638ad997cf35220",
		},
		{
			pubkeyHex:   "b15fad558737229f8816fcba8fbef805bd420c03e392d118c69bdf01890c4924",
			extendedHex: "f5810477e37554728837f097e1b170d1d8c95351c7fff8abbbfc624e1a50c1b9",
		},
		{
			pubkeyHex:   "ec8c1f10d8e9da9cf0d57c4a1f2c402771bed7970109f3cf21ad32111f1f198f",
			extendedHex: "a697e0a3f09827b0cf3a4ffb6386388feda80d30ffffcbd54443dafcba162b28",
		},
		{
			pubkeyHex:   "a989647bf0d70fdb7533b8c303a2a07f5e42e26a45ffc4e48cff5ba88643a201",
			extendedHex: "450fd73e636f94d0d232600dd39031386b0e2ecde4105124fc451341da9803db",
		},
		{
			pubkeyHex:   "7159971b03c365480d91d625a0fadc8e3a632c518acf0dbec87dd659da70e168",
			extendedHex: "377bc43c038ac46cf6565aa0a6d6bf39968c0c1142755dba3141eeebf0acdf5d",
		},
		{
			pubkeyHex:   "e39089a64fedac4b2c25e36312b33f79d02bf75a883f450f910915b8560a3b06",
			extendedHex: "77efa7db1be020e77596f550de45626824a8268095d56a0991696b211cb329cc",
		},
		{
			pubkeyHex:   "2056b3c6347611bb0929dad00ec932a4d9bec0f06b2d57f17e01ffa1528a719e",
			extendedHex: "b6072c2be2ce928e8cbbb87e8eb7e06975c0f93b309dd3b6a29edaad2b56f99b",
		},
		{
			pubkeyHex:   "2c026793146e81b889fc741d62e06c341ce263560d57cd46d0376f5b29174489",
			extendedHex: "8f1f64b67762aa784969e954c196a2c6610addc3604aa3291eb0b80304dfe9ef",
		},
		{
			pubkeyHex:   "be6026d6704379c489fa7749832b58bdb1a9685a5ffb68c438537f2f76e0011f",
			extendedHex: "0072569a4090a9ad383a205bb092196c9de871c22506e3bb63d6b9d1b2357c96",
		},
		{
			pubkeyHex:   "f4db802d5c6b7d7b53663b03d988b4cd0c7cad6c26612c5307754a93ebdc9710",
			extendedHex: "f21bc9be4cb28761f6fe1d0a555ad5e9748375a2e9faea25a1df75cc8d273e18",
		},
		{
			pubkeyHex:   "c27d79a564c56b00956a55090481e85fbc837fd5fb5e8311ecb436e300c07e3a",
			extendedHex: "1b1891e6abec74621501450cd68bb1eeaa5b2fffff4ec441a55d1235ff3a0842",
		},
		{
			pubkeyHex:   "a1e2f93c717cad32af386efa624198973df5a710963dd19d4c3ac40032a3a286",
			extendedHex: "69c60571e3f9f63d2bfb359386ae3b8cd9e49a2e9127753002866e85c0443573",
		},
		{
			pubkeyHex:   "76920d7b1763474bc94a16433c3c28241a9acdee3ff2b2cb0e6757ba415310aa",
			extendedHex: "c1b409169f102b696fc7fa1aa9c48631e58e08b5132b6aadf43407627bb1b499",
		},
		{
			pubkeyHex:   "57ac654b29fa227c181fff2121491fcb283af6cbe932c8199c946862c0e90cb2",
			extendedHex: "a204e8d327ea93b0b1bd74a78ffc370b20cea6455e209f2bc258114baa16d728",
		},
		{
			pubkeyHex:   "88e66cfaef6432b759c50efce885097d1752252b479dac5ed822fa6c85d56427",
			extendedHex: "6fb84790d3749a5c1088209ee3823848d9c19bf1524215c44031143dd8080d70",
		},
		{
			pubkeyHex:   "c1e55da929c4f8f793696fc77ff4e1c317c34852d98403bfd15dd388ee7df0df",
			extendedHex: "2f41e76f15c5b480665bd84067e3b543b85ce6de02be9da7a550b5e1ead94d34",
		},
		{
			pubkeyHex:   "29e9ace5aa3c5a572b13f4b62b738a764d90c8c293ccb062ad798acbab7c5ef4",
			extendedHex: "bce791aba1edc2a66079628fd838799489ab16b0a475ce7fe62e24cc56fe131c",
		},
		{
			pubkeyHex:   "f25b2340689dadacaa9a0ef08aee8447d80b982e8a1ea42cf0500a1b9d85b37d",
			extendedHex: "f7f53aa117e6772a9abc452b3931b0a99405ac45147e7c550ac9fcf7ffe377b5",
		},
		{
			pubkeyHex:   "0cb6c47fc8478063b33f5aed615a05bcc84d782c497b6cc8e76ec1fa11edbfdb",
			extendedHex: "7a0b58b03147e7c9be1d98de49ead2ce738d0071b0af8ca03cc92ceb26fc2246",
		},
		{
			pubkeyHex:   "7bd7287d7c4b596fe46fe57a6982c959653487bea843a77dd47d40986200d576",
			extendedHex: "343084618c58284c64a5ff076f891be64885dc2ac73fa1567f7b39fde6b91542",
		},
		{
			pubkeyHex:   "e4984bf330708152254fb18ecef12d546afd24898a3cf00fba866957b6ee1b82",
			extendedHex: "c70e88b061656181fbd6ff12aca578fb66de5553c756ea4698a248b177185bc6",
		},
		{
			pubkeyHex:   "cefd6c3cb9754ea632d6aea140af017de5ea12e5184f868936b74d9aa349d603",
			extendedHex: "4b476502a8a483aadd50667f262f95351901628dd3a2aac1a5a41c4ea03f1647",
		},
		{
			pubkeyHex:   "da5d0f33344ee7f3345204badf183491b9452b84bccc907602c7bad43e5cf43e",
			extendedHex: "9561b9e61241625e028361494d4fa5cd78df4c7219fa64c8fede6d8421b8904a",
		},
		{
			pubkeyHex:   "d6f0a4f8c770a1274a76fd7ae4e5faf7779249263e1aaecc6f815cf376f5c302",
			extendedHex: "cd5c55820be10f0d38feb81363ede3716a9168601a0dd1ce3109aab81367d698",
		},
		{
			pubkeyHex:   "b6bf32491d12a41c275d8518fc534d9a0d17aade509e7e8b8409a95c86167307",
			extendedHex: "4aae534abbd67a9a8f2974154606c0e9be8932e920c7a5e931b46a92859acf82",
		},
		{
			pubkeyHex:   "0f930beaad041f9cefd867bc194027dd651fb3c9bda5944ececdba8a7136b6d3",
			extendedHex: "521708f8149891b418d0920369569a9d578029c78f8e41c68a0bb68d3ad5df60",
		},
		{
			pubkeyHex:   "49b1fe0f97be74b81e0b047027b3e9f726fa5e90a67dafa877309397291c06c5",
			extendedHex: "0852e59dfae5ec32cce606c119376597bce5cd4d04879d329f74e3ec66414cd3",
		},
		{
			pubkeyHex:   "4d57647d03f2cfbd4782fcc933e0683b52d35fc8d37283e6c7de522ddfa7e698",
			extendedHex: "cbeb9ebfbbc49ec81fac3b7b063fecac1bb40ea686d3ffb08f82b291715cd87f",
		},
		{
			pubkeyHex:   "4ea3238c06fc9346c7421ff85bc0244b893860b94bc437378472814d09b2e99f",
			extendedHex: "a1fbae941adc344031bbdf53385dfdc012311490a4eb5e9a2749a21b27ce917a",
		},
		{
			pubkeyHex:   "0cd3609f5c78b318cb853d189b73b1ee2d00edd4e5fce2812027daa3fcb1fed1",
			extendedHex: "0c7a7241b16e3c47d41f5abbf205797bd4b63fc425a7120cb2a4bf324e08ae74",
		},
		{
			pubkeyHex:   "d74ab71428e36943c9868f70d3243469babd27988a1666a06f499a5741a52e3e",
			extendedHex: "65b7c259f3b4547c082b2a7669b2b363668c4d87ac14e80471317b03b34e5216",
		},
		{
			pubkeyHex:   "f6b151998365e7d69bcbce383dd2e8b5bf93b8b72f029ff942588208c1619591",
			extendedHex: "6ce840ce5dfbca238665c1e6eddb8b045aa85c69b5976fc55ab57e66d3d0a791",
		},
		{
			pubkeyHex:   "207751de234b2bd7ec20bdd8326210c23aa68f04875c94ad7e256a96520f25d6",
			extendedHex: "fc8f79ab3af317c38bfb88f40fb84422995a0479cfa6b03fa6df7f4e5f2813fb",
		},
		{
			pubkeyHex:   "62291e2873f38c0a234b77d1964205f3f91905c261d3c06f81051a9b0cb787cb",
			extendedHex: "076d1d767457518e6777cb3bd4df22c8a19eb617e4bbccd1b0bd37522d6597a5",
		},
		{
			pubkeyHex:   "4b060df2d2854036751d00190ee821cb0066d256d4172539fdfa6fbd1cdfe1f9",
			extendedHex: "59866e927c69e7de5df00dc46c0d2a1ddf799d901128ff040cebb8fd61b95da4",
		},
		{
			pubkeyHex:   "ac8daf73f9c609bb36bce4fdeec1e50be5f22de38c3904fabcf758f0fc180bc7",
			extendedHex: "7d8dc4e956363b652468a5fecafd7c08d48a2297e93b8edcb38e595fdd5a1fde",
		},
		{
			pubkeyHex:   "fef7b6563fd27f3aab1d659806b26b8f2ec38bc8feefad50288383c001d1c20f",
			extendedHex: "e6e42547f12df431439d45103d2c5a583248f44554a98a3a433cf8c38b11805d",
		},
		{
			pubkeyHex:   "40a3d6871c76ecc6bb7b28324478733e196cc11d062dd4c9265cf31be5cf5a97",
			extendedHex: "8c55a3811c241a020b1be202a58d5defbc4c8945d73b132570b47dd7c019ccf0",
		},
		{
			pubkeyHex:   "0cd71e7e562b2b47f4bc8640caf20e69d3a62f10231b4c7a372c9691cff9ac3c",
			extendedHex: "fb8e4e3de479b3bf1f4f13b4ed5507df1e80bd9250567b9d021b03339d6e7197",
		},
		{
			pubkeyHex:   "40a4e62800a99b7a26e0b507ffb29592e5bdba25284dc473048f24b27d25b40a",
			extendedHex: "90ae131d29ee4a71cd764ab26f1ca4e6d09a40db98f8692b345c3a0e130dc860",
		},
		{
			pubkeyHex:   "1ddf35193cf52860bfe3e41060a7f44281241c6ae49cd541d24c1aca679b7501",
			extendedHex: "3b4f50013895c522776ced456329c4e727de03575f6b99ae7d238a9f70862121",
		},
		{
			pubkeyHex:   "014e0fa8ce9d5df262b9a1765725fde354a855de8aef3fc23684e05dd1ba8d34",
			extendedHex: "3857f57776a3cb68721bcb7f1533a5f9fb416a1dc8824d719399b63a142d24de",
		},
		{
			pubkeyHex:   "09987979b0e98d1d5355df8a8698b8f54d3a037d12745c0a4317fe519c3df9cc",
			extendedHex: "32a181e2b754aeced214c73ac459c97d99e63317be3eb923344c64a396173bca",
		},
		{
			pubkeyHex:   "51e9e8ec4413e92dbaaba067824c32b018487a8d16412ed310507b4741e18eed",
			extendedHex: "0356b209156b4993fd5d5630308298429a1b0021c19bedecb7719ac607cfa644",
		},
		{
			pubkeyHex:   "14d91313dfe46e353310e6a4a23ee15d7a4e1f431700a444be8520e6043d08d9",
			extendedHex: "6f345f4018b5d178d9f61894d9f46ac09ff639483727b0d113943507cee88cfd",
		},
		{
			pubkeyHex:   "0d5af9ace87382acfffb9ab1a34b6e921881aa015d4f6d9c73171b2b0a97600d",
			extendedHex: "a8dbf36c85bebe6a7b3733e70cd3cd9ed0eb282ca470f344e5fcf9fe959f2e6e",
		},
		{
			pubkeyHex:   "996690caac7328b19d20ed28eb0003d675b1a9ff79055ab530e3bf170eb22a94",
			extendedHex: "14340d7d935cffce74b8b2f325c9d92ce0238b51807ef2c1512935bb843194ce",
		},
		{
			pubkeyHex:   "ad839c4b4c278c8ebe16ff137a558255a1f74646aa87c6cd99e994c7bb97ce8a",
			extendedHex: "d4f2da327ffded913b50577be0e583db2b237b5ca74da648e9b985c247073b76",
		},
		{
			pubkeyHex:   "26fc2eeeee983e1300d72362fdff42edf08038e4eee277a6e2dbd1bd8c9d6560",
			extendedHex: "3468b8269728c2c0bfc2e53b1575415124798bc0f59b60ea2f14967fc0ca19ce",
		},
		{
			pubkeyHex:   "db33cecaf4ee6f0ceba338cc5fabfb7462cd952a9c9007357ff3f0ca8336f8bc",
			extendedHex: "0bab38f58686d0ff770f770a297971510bc83e2ff2dfead34823d1c4d67f11af",
		},
		{
			pubkeyHex:   "a0ee84b3c646526fb8787d26dcd9b7fe9dc713c8a6c1a4ea640465a9f36a64df",
			extendedHex: "4d7a638f6759d3ec45339cd1300e1239cca5f0f658ca3cd29bc9bdb32f44faf0",
		},
		{
			pubkeyHex:   "6a702e7899fcf3988e2b6b55654c22e54f43d3fa29de19177bdff5b2295fe27f",
			extendedHex: "145d5748d6054fb586568e276f6925aef593a5b9c8249ad3dbef510af99b4307",
		},
		{
			pubkeyHex:   "30ce0fd4f1fac8b62d613b8ee4a66deef6eb7094bd8466531050b837460f6971",
			extendedHex: "f3aa850d593ba7cef01389f7e1916e57617f1d75cd42f64ce8f5f272384b148c",
		},
		{
			pubkeyHex:   "3aa31d4ad7046ad13d83eb11c9a6e90eb8483a374a77a9a7b2a7cc0978fefa76",
			extendedHex: "2fe0827dc080d9c1e7ec475a78aa7ae3c86d1a35f4c3f25f4a1f7299cacf018a",
		},
		{
			pubkeyHex:   "8562a5a91e763b98014523ebb6e49120979098f89c31df1fde9eb3a49a15b20f",
			extendedHex: "ae223bf85e2009a9daf5fd8a14685e2e1e625fc88818b2fd437dd7e109a48f59",
		},
		{
			pubkeyHex:   "ccf9c313a47b8dbf7ce42c94b785818bc24134d95b6d22acc53c1ec2be29cf27",
			extendedHex: "3e79fce6fe5aa14251b6560df4b76e811d7739eec097f27052c4403a283be71d",
		},
		{
			pubkeyHex:   "d1e33cd6f8918618d5fb6d67ad8de939db8beaec4f115551eac64479b739b773",
			extendedHex: "613fffcbe1bf48bb2d7bfd64fd97790a06025f8f2429edddb9ac145707847ecf",
		},
		{
			pubkeyHex:   "81eaeced34dd44e448d5dafa5715225e4956c90911c964a96ff7aa5b86b969bc",
			extendedHex: "8f81177495d120a1357380164d677509b167f2958eb8b962b616c3951d426d8c",
		},
		{
			pubkeyHex:   "2bc001a29f8eab1c7377de69957ba365fb5bdaf9c2c220889709af920dfe27d3",
			extendedHex: "9bcb3010038f366fa4c280eed6e914a23bfc402594d0b83d0e66730a465a565b",
		},
		{
			pubkeyHex:   "6feeb703c05e86c58d9fc5623f1af8657ecd1e75a14d18c4eedb642a8a393d16",
			extendedHex: "6544628ba67ed0e14854961739c4d467fcf49d6361e39d32ea73dabeae51e6c3",
		},
		{
			pubkeyHex:   "e8ff145a7c26897f2c1639edd333a5412f87752f110079f581ccdc87fcce208c",
			extendedHex: "d4b5a6e06069c7e012e32119f8eda08ff04a8dfa784e1cf1bced455a4d41d905",
		},
		{
			pubkeyHex:   "80488131dcb2018527908dbf8cdf4b823ef0806dc1d360f4da671004ef7ff74d",
			extendedHex: "9984a79d9fd4f317768b442161116eef84e2ca49e938642b268fd64312d59a27",
		},
		{
			pubkeyHex:   "d8c4ca60446849a784d1462aa26a3b93073ff6841cb2da3ef52ab9785b00b1fd",
			extendedHex: "da5ec1562e7de2382d35728312f4eea3608d4dba775c1c108de510e1ce97d059",
		},
		{
			pubkeyHex:   "68645728dfc6b9358dfb426493238ba38f24a2f46a3e89edb47d212549939cb7",
			extendedHex: "d3253aa7235113dcc1b577d3bb80be34f528398815a653dbdbacbcbdfd5887a1",
		},
		{
			pubkeyHex:   "4e8eb97ba2d1046e1b42e67530a61441e31c84e5e5e448d8e8dbe75d104eaccb",
			extendedHex: "de94f73e83222aa0e39b559d4fef70387b0815b9b2f6beff5da67262d8f0eb3e",
		},
		{
			pubkeyHex:   "104ff03122ffdf59b22b8c0fe3d8f2ef67d02328e4d5181916d3d2a92f9a0bb7",
			extendedHex: "1517ccf69c0328327e1cf581f16944ff66bc91c37e1cd68a99525415e00b7c9f",
		},
		{
			pubkeyHex:   "80f23aae7356ae9a2f9f7504495a731214d26f870fb7df68fdc00b233494156f",
			extendedHex: "7aef046b0a70f84e8d239aa95e192b5a3fffa0fae5090c91273e8996beca9e38",
		},
		{
			pubkeyHex:   "2424b33235955a737ebddbf1c6c59cd8778af74da3bd3e658447666a2ab2f557",
			extendedHex: "d19e2be8d482950fbdae429618da7a9daedb8c5944dea19cd1b6b274e792231b",
		},
		{
			pubkeyHex:   "0adc839d2b8f099e4341a4763b074c06318d6bcbd1ec558d20a9820c4a426463",
			extendedHex: "cea5da12a84e5c20011726d9224a9930bec30f9571762dd7ca857b86bd37d056",
		},
		{
			pubkeyHex:   "46c84d53951f1ba23c46a23d5d96bf019c559aa5d2d79e4535cfcdb36f38ce25",
			extendedHex: "2a913a01a6f7dd78a43cdd5354d1160d9a5f0d824c489a892c80eba798a77567",
		},
		{
			pubkeyHex:   "99bdaaf68555ccdc93d97c3a0fb4c126a1aa8b1202194a1a753401a6cae21055",
			extendedHex: "1f645efe173577a092f2d847cc966e28ba3b36397fe84c96dfa4724ed4fcfdf9",
		},
		{
			pubkeyHex:   "c540ff78f1e063ad26ffa69febb8818c9f2a325072c566091ad816e40fe39af4",
			extendedHex: "de7a762262c91ab4beccc0713233cb91163aec43e34de0dbcfad0c431e8a9722",
		},
		{
			pubkeyHex:   "de8b1ff8978cd5e02681521542b7b6c3c2f8f4602065059f83594809d04e3dda",
			extendedHex: "290601e75207085bff3e016746e55a80310a76dea9ef566c24181079c76da11c",
		},
		{
			pubkeyHex:   "d555994c8a022e52602d2a8bdd01fc1bfa6b9ab6734ff72a1bd5f937de4627f8",
			extendedHex: "5f6794e874f48c4b362d0a24207374c2d274e28de86351afc6ddb95d8cc2fd62",
		},
		{
			pubkeyHex:   "19db72f703fe6f1b73f21b6ba133ae6b111ae8cc496d3aa32e02411e34c0d8d7",
			extendedHex: "42f159f43d2d62b8cf8a47d5f1340c5cf070e9860fc60de647c55d50fe9f5607",
		},
		{
			pubkeyHex:   "23a87a258c2a5d1353aa2d5946f9e5749b92f85e3c58e1d177c3b6c3dcac809c",
			extendedHex: "e5685016f79d5e87d1fecb3e2a0fe64e4875f7accd2f6649d7f6b16317549cb1",
		},
		{
			pubkeyHex:   "43e1738d7d1b5b565f5fc78e81480f7edf9a4dc18f104fc4be95135b98931b17",
			extendedHex: "650f5b682e45f2d0c5d5e8bcfd9e0cda7d9071b55ecbfaf5e3b59941cd7479f2",
		},
		{
			pubkeyHex:   "a9d644de0804edf62dee613efa2547e510990a9b7a987ebe55ec74c23873a878",
			extendedHex: "52ad329f88499a4f110e6a6cba1f820012d8db6ccb8f6495ab1e3eb5a24786e1",
		},
		{
			pubkeyHex:   "11f2b5d89a0350d7c8727becf0f4dd19bd90f8c94ff207132ab13282dd9b94e6",
			extendedHex: "b798a47bb98dc2a8f99deaf64d27638e33a0d504c5d2fbee477a2bc9b89e2838",
		},
		{
			pubkeyHex:   "5e206e3190b3b715d125f1a11fff424fb33e36e534c99ddde2a3517068b7dcc4",
			extendedHex: "2738e9571c96b2ddf93cb5f4a72b1ea78d3731d9555b830494513c0683c950ca",
		},
		{
			pubkeyHex:   "efc3d65a43d4f10795c7265a76671348f80173e0f507c812f7ae76793b99c529",
			extendedHex: "cf4434d18ce8167b51f117fe930860143c46e1739a8db1fba73b6b0de830d707",
		},
		{
			pubkeyHex:   "81f00469788aad6631cf75b585ae06d43ec81c20479925a2009afac9687dff60",
			extendedHex: "c335b5889b36ba4b4175bb0d986807e8eedb6f6b7329b70b922e2ab729c4202a",
		},
		{
			pubkeyHex:   "9ef5ff329b525ee8f5c3ac38e1dba7cb19985617341d356707c67ff273aed02d",
			extendedHex: "bef9f9e051ba0e24d1fdf72099cf43ecdd250d047fb329855b5372d5c422db9e",
		},
		{
			pubkeyHex:   "3fa1401bd63132cf8b385c0fa65f0715ba1fe6161e41d59f8033ae2b22f63fa1",
			extendedHex: "8289a1cb3c2dae48879bb8913fafe2d196cc2fdab5f2a77607910efd33eae6df",
		},
		{
			pubkeyHex:   "6559836fd0081fa38a3f8d8408b564e5698b9797cf5e15f7f12a7d2c84511989",
			extendedHex: "28d405a6687d2ecc90c1c66bf0454d58f3fa38835743075e1db58c658e15a104",
		},
		{
			pubkeyHex:   "8e0882d45f0e4c2fb2839d3be86ff699d4b2242f5b25ac5a3c2f65297c7d2032",
			extendedHex: "2771fdcf9135a62007adb5f0004d8222f0e42f819c81710aa4dc3ab2042bebf3",
		},
		{
			pubkeyHex:   "1d91dc4dd9bd82646029d13aca1af96830c1d8a0400ddebeb14b00c93501c039",
			extendedHex: "7792c62e897f32cbc9c4229f0d28f7882ceeae120329a1cd35f76a75ac704e93",
		},
		{
			pubkeyHex:   "09527f9052acbbdd7676cbbd9534780865f04a27aaadad2b7d4f1dac68883cf0",
			extendedHex: "b934220cde1327f2dc6af67bcb4124bf424d5084ef4da945e4daad1717cd0bb8",
		},
		{
			pubkeyHex:   "2362e1abe73e64cdd2ca7f6c5ea9f467213747dd3f2b7c6e5df9cb21e03307d7",
			extendedHex: "676b7122b96564358bbaaf77e3a5a4db1767e4f9a50f6ddd1c69df4566755af9",
		},
		{
			pubkeyHex:   "26c2dd2356e9b6c68a415b25f91d18614dc8500c66f346d28489da543ee75a94",
			extendedHex: "0f4fd7086acd68eb7c9fa2410e2ecf18e34654eb44e979bc03ce436e992d5feb",
		},
		{
			pubkeyHex:   "422dc0a09d6a45a8e0b563eeb6a5ee84b08abd3a8cb34ff93f77ba3b163f4042",
			extendedHex: "631f1b412ff5a0fccbe53a02b4a3deaa93a0418ed9874df401eb698ef75d7441",
		},
		{
			pubkeyHex:   "ceecdf46f57ef3f36ff30a1a3579b609340282d1b26ab5ddef2f53514e91bab1",
			extendedHex: "9bc6f981fe98d14a2fc5b01a8134b6d35e123ec9ab8a3f303e0a5abb28150e2e",
		},
		{
			pubkeyHex:   "024a9e6e0d73f28aa6207fb1e02ce86d444d2d46f8211e8aaab54f459db91a5a",
			extendedHex: "5fb0c1d2c3b30f399102104ea1874099fa83110b3d9c1fcfffb2981c98bf8cdf",
		},
		{
			pubkeyHex:   "5b8e45e269c9ccac4c68e532a72b29346d218f4606f37a14064826a62050e3a8",
			extendedHex: "c7be46a871b77fc05ce891d24bd6bd54d9775b7ef573c6bc2d92b67f3604c1d1",
		},
		{
			pubkeyHex:   "9a6593a385c266389eef14237874b97bdcd1823c3199311667d4853c2d12aa81",
			extendedHex: "9f55ee9d94102d2b9c5670f30586cf9823bf205b4d4fe088c323e87c4e10f26f",
		},
		{
			pubkeyHex:   "27377e2811598c3569b92990865d39b72c7a5533e1be30f77330863187c11875",
			extendedHex: "abd82bc726f2710a8b87e4c1cf5a069f0ae800de614468d3ff35639983020197",
		},
		{
			pubkeyHex:   "7cacfaa135fb7d568b8dce8ea9136498b1b28c6d1020af45d376288d78d411f0",
			extendedHex: "229fccd49744c0692508af329224553d21561ee6062b2b8a21f080f73da5bd97",
		},
		{
			pubkeyHex:   "52abd90a5542d6496b8dec9567b020f30058e29458d64f2d4f3ad6f3bfc1a5a0",
			extendedHex: "874e82ced7cf77577b3374087fb08a2300b7f403de628310c26bdb3be869d309",
		},
		{
			pubkeyHex:   "5c8eebe9d12309187afa8d0d5191de3fdb84e5a05485d7cd62e8804ce7fdc0bc",
			extendedHex: "12b7537643488aa8b9dcc4bae040cd491f8b466163b7988157b0502fb6c9177f",
		},
		{
			pubkeyHex:   "6ca3dd5c7a21a6bf65d6eefbe20a66e9b1d6b64196344be0c075f47aea48e3aa",
			extendedHex: "5e1d0705ee24675238293b73ab1d98359119d4b328275be2460cc6ee4d19cc88",
		},
		{
			pubkeyHex:   "d7e6cd0d39b4308c2a5ee547c4569c8bb3887e49cedece62d218d7c3c5277797",
			extendedHex: "793dc4397112dfd9a8f4e061f457eb6d6fbb1d7a58c40bad5f16002c64914186",
		},
		{
			pubkeyHex:   "9cb6de8ba967cca0f0f861c6e20546f8958446595c01c28dae7ba6cfa09d6b14",
			extendedHex: "ba1a2f7502b58fee3499c20e35fa01bb932e7a7c4a925dc04fbf5d90f33cfb5e",
		},
		{
			pubkeyHex:   "8ef9c7366733a1edcd116238cdbd177d61222d5c3e05b30ef6b85014cbcb6b79",
			extendedHex: "8fc89664722947164ac9b77086aed319897612068f56ecd57f47029f14671603",
		},
		{
			pubkeyHex:   "7f317a34e4fb7de9f69cb107ffc0e57fd9f5c85b85ccb5319d05cebfc169924a",
			extendedHex: "4b71c42339c73db7d710cd63f374d478a6c13bdc352cff40e967282268965ba7",
		},
		{
			pubkeyHex:   "15beef8d9687b92918a903b01d594859db4e7128263c8db0cae9d423ff962c1e",
			extendedHex: "cd75e6323952f6ac88f138f391b69f38c46d70b7eda61f9e431725b6f1d514a5",
		},
		{
			pubkeyHex:   "7a1c04c9af8fc6649833fe81e96f0199fcfe94959256cbe1490075fc5be0904e",
			extendedHex: "0368270cd979439ae0a9552a5d6c9f959e4247fcf920d9e071464582e79c04b1",
		},
		{
			pubkeyHex:   "c854c583d338615f85f69061e0fa9c9d7c5bbbfe562e8774fef3be556fe8bb63",
			extendedHex: "061620171d7320f64bee98414ff7200a1f481521d202fb281cab06be73b80402",
		},
		{
			pubkeyHex:   "0fb8af5aba05ad2503edf1cfad5a451da088e7e974772057cd991a4e0601a3eb",
			extendedHex: "d3cbc20384a4420143fcce2cb763b0c15bec4f3267d1bdad3c34c1ee6b790f5e",
		},
		{
			pubkeyHex:   "9a251cf59e84a9da5630642f9671c732440caa8fcf4c92446a7e5f5ef99da46c",
			extendedHex: "9b9679086a433f2077f40bcd4c7545fb5cc87e7dbb8bba468d53cb04a74361a0",
		},
		{
			pubkeyHex:   "8c632e357cef00e0911eb566f8cc809136b3f5ac1e82d183e4d645cef89fa155",
			extendedHex: "5e06b0f4f278fa1ccb5431866e0b35171cdb814e2e82b9189ce01d8d8a1b2408",
		},
		{
			pubkeyHex:   "4aa4c31463475086a5d96b3ff550340567ab3b4a86fa3f01cfe9be18bc4dcb54",
			extendedHex: "76a2916cfc093f27992e1f07b50f431d61d58e255507e208cd29ea4d3bc56623",
		},
		{
			pubkeyHex:   "1d33d9aadb949346e3c78d065a0f5262374524f4cb97a7390c8cdaede7ca6578",
			extendedHex: "9ad2f757f499359903031adea6126c577469c4e834a2959e3ac08ee74b13783c",
		},
		{
			pubkeyHex:   "d9217b9a070df20c4d2f0db42ff0bb36bfba9f51b0b6df8fdfe150405dce4934",
			extendedHex: "65a843c522b4b8ec081a696a0d2dd8dfdfea45db201de7a5889a1446c6dff8c7",
		},
		{
			pubkeyHex:   "b665b2ca8a285e44ba84e785533b56496a5319730dbb95bc14d3bdfece7544dc",
			extendedHex: "8a804cd13457497b0a29eeca2cecfaa858766ec1d270a0e0c6785b43fd49b824",
		},
		{
			pubkeyHex:   "43b5cbcc21b3404bca97fa9a661940fe64d40f3ca569310e50b1bb0173c4d5ee",
			extendedHex: "6c12fffb540d536060bb8b96cf635c1b2cbaa4d875a8d2fb0bf79a690363df19",
		},
		{
			pubkeyHex:   "11c58f20562c00dec5bb4456be07cd98186837e9af38d50d45f5e7b6f0f9000d",
			extendedHex: "cee76b567586f66dadd38c01213bfc1a17d38e96a495efb4c26063dc498ba209",
		},
		{
			pubkeyHex:   "b069a980b51d8e030262db0b30069e660f4a3f6f8075d1790c153ba12b879f8b",
			extendedHex: "262391b00bdee71d1d827b2cfe50b46c29e265934dc91959bd369aca0cc6444e",
		},
		{
			pubkeyHex:   "75274bfd79bf33eb2f9ab046d34528af9a71811e7e3d55c20eb049c81ac692d8",
			extendedHex: "cb93c850e36896fe6626e97c53652af6736ec3ba0641c7765d0cca2bad2352de",
		},
		{
			pubkeyHex:   "5cdb6a24d9736a00f197d9707949fedc5405f367744fe8c83b7cff650302b589",
			extendedHex: "8b4ac03123fab9275dcf340345a1b11fba48ef106d410ba2e0e6f6457037a419",
		},
		{
			pubkeyHex:   "07fdc85f809f95a07b59b084402bf91c512ebbe05c7657d6ba27a9e7e121e3e2",
			extendedHex: "61182b3def063630e11de648a278032bcb75949f3a24ef5a133da87830ae5c4e",
		},
		{
			pubkeyHex:   "a4188ca634cbb796f9927822e343d7b267e0a609c1a0ffa4dcf3726b9ffcc8a2",
			extendedHex: "a911e4899fda28fd6337d708d34553ac5e810ee4938f6f7d9d6e521cab069edb",
		},
		{
			pubkeyHex:   "3c128ec5c955ea189a5789df2c892e94193a534a9d5801b8f75df870bc492a69",
			extendedHex: "59eef5ee9df0f681df5b5c67ead1f06b059a8a843837b67f20cce15779608170",
		},
		{
			pubkeyHex:   "51a4cc7ec4a14a98c0731e9de7f3ce0779123222d95455e940f2014a23729ec8",
			extendedHex: "105863ccda076af7290d1bf9ec828651dc5811159839044d23f1c3e31a11c5e2",
		},
		{
			pubkeyHex:   "1b901a31acbb7807c3309facdc7d04bc3b5a4aa714e6e346bd1c6ad4634e6534",
			extendedHex: "01b3c0000b6c6b471c67c6ab3f9c7a500beaea5edb5c8f2b34df91b69ff67f21",
		},
		{
			pubkeyHex:   "d2f2c8d79cfa2e7cb2db80568ba62ca0576741acfbe5e2baa0d9b3c424a7c84d",
			extendedHex: "7df9d9088022bd1ce6814d6f8051eef27a650ee38e789b184da2691efd27139d",
		},
		{
			pubkeyHex:   "04dcb7644fdfc12d8e34d6e57d7769db939b4a149ed2b81aa51a74ee90babe19",
			extendedHex: "6cff0ab2dd3b32ba1bd1a78e3661722f3f10003a01ce83e430970557decedb2c",
		},
		{
			pubkeyHex:   "222798c6841eeaa07e7b7e29686942d7c7f9afc38d09360c8e1f52f2b7debd12",
			extendedHex: "133e3a04ec82aa9b8dbbec18cadbafff446d1270bf7c6f3f97ddd3906dae2468",
		},
		{
			pubkeyHex:   "4f7277c3ef247a0689b486ad965f969c433fc63e95d7310e789c4708418ccabc",
			extendedHex: "7e0f2c984dd3cffb35458938c95fe92acf2e697aed060b0e3377c7a07e53c494",
		},
		{
			pubkeyHex:   "359b4d6709413243ae2c5409ea02714a9f8961bbbb64a91e81daf01e18c981bf",
			extendedHex: "eab69af2cb7f113ad6a27035c0399853d10bd0b99291fad37794d100f7530431",
		},
		{
			pubkeyHex:   "6cea3c6a9eb38f60329537170aa4db8dbb869af2040061e53b10c267daf6568c",
			extendedHex: "da9a97f4fa96bd05dade5e2704a6a633ba4dbe5080a1e831cda888e9d4f86615",
		},
		{
			pubkeyHex:   "3dddecb954ef0209bcf61fd5b46b6c94f2384ef281c48a20ffee74f90788172d",
			extendedHex: "af9899c31f944617af54712f93d1a2b4944e48867f480d0d1aec61f3b713e32d",
		},
		{
			pubkeyHex:   "9605247462f50bdf7ff57fe966abbefe8b6efa0b65b5116252f0ec723717013f",
			extendedHex: "fc8f10904d42a74e09310ccf63db31a90f1dab88b278f15e3364a2356810f7e9",
		},
		{
			pubkeyHex:   "a005143c4d299933f866db41d0a0b8c67264f5d4ea840dd243cb10c3526bc077",
			extendedHex: "928df1fe9404ffa9c1f4a1c8b2d43ab9b81c5615c8330d2dc2074ac66d4d5200",
		},
		{
			pubkeyHex:   "f45ce88065c34a163f8e77b6fb583502ed0eb1f490f63f76065a9d97e214e3a9",
			extendedHex: "41bd6784270af4154f2f24f118617e2d7f5b7771a409f08b0f2b7bbcb5e3d666",
		},
		{
			pubkeyHex:   "7b40ac30ed02b12ff592a5479c80cf5a7673abfdd4dd38810e40e63275bc2eed",
			extendedHex: "6c6bf5961d83851c9728801093d9af04e5a693bc6cbad237b9ac4b0ed580a771",
		},
		{
			pubkeyHex:   "9f985005794d3052a63361413a9820d2ce903198d6d5195b3f20a68f146c6d5c",
			extendedHex: "88bcac53ba5b1c5b44730a24b4cc2cd782298fc70dc9d777b577a2b33b256449",
		},
		{
			pubkeyHex:   "31b8e37d01fd5669de4ebf78889d749bc44ffe997186ace56f1fb3e60b8742d2",
			extendedHex: "776366b44170efb130a5045597db5675c6c0b56f3def84863c6b6358aa8dcf40",
		},
	}
	for _, test := range tests {
		pubkeyBytes := HexToBytes(test.pubkeyHex)
		pubKey := PubKey(pubkeyBytes)
		want := HexToBytes(test.extendedHex)
		ecPoint := new(edwards25519.ExtendedGroupElement)
		HashToEC(&pubKey, ecPoint)
		var got [32]byte
		ecPoint.ToBytes(&got)
		if want != got {
			t.Errorf("%x: want %x, got %x", pubkeyBytes, want, got)
		}
	}
}

func TestCreateSignature(t *testing.T) {
	numTries := 50
	numMixins := 10
	for i := 0; i < numTries; i++ {
		hash := Hash(RandomScalar())
		privKey, _ := NewKeyPair()
		mixins := make([]PubKey, numMixins)
		for j := 0; j < numMixins; j++ {
			_, pk := NewKeyPair()
			mixins[j] = *pk
		}
		keyImage, pubKeys, sig := CreateSignature(&hash, mixins, privKey)
		if !VerifySignature(&hash, &keyImage, pubKeys, sig) {
			var pubKeyStr string
			for _, pk := range pubKeys {
				pubKeyStr += fmt.Sprintf("%x ", pk)
			}
			t.Errorf("%d: failed on verify: %x %x %s%x", i, hash, keyImage, pubKeyStr, sig.Serialize())
		}
	}
}

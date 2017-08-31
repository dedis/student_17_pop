#./pop -c cl1/ org link dedis.ch:9200 811383
#./pop -c cl2/ org link dedis.ch:9202 298150
#./pop -c cl3/ org link dedis.ch:9204 219184


#./pop -c cl1 org config pop_desc1.toml pop_merge.toml
#./pop -c cl2 org config pop_desc1.toml pop_merge.toml
#./pop -c cl2 org config pop_desc2.toml pop_merge.toml
#./pop -c cl3 org config pop_desc2.toml pop_merge.toml
#./pop -c cl3 org config pop_desc3.toml pop_merge.toml
#./pop -c cl1 org config pop_desc3.toml pop_merge.toml
#
#./pop -c cl1 org public $pub1 $pop_hash1
#./pop -c cl2 org public $pub1 $pop_hash1
#./pop -c cl2 org public $pub2 $pop_hash2
#./pop -c cl3 org public $pub2 $pop_hash2
#./pop -c cl3 org public $pub3 $pop_hash3
#./pop -c cl1 org public $pub3 $pop_hash3
#
#./pop -c cl1 org final $pop_hash1
#./pop -c cl2 org final $pop_hash1
#./pop -c cl2 org final $pop_hash2
#./pop -c cl3 org final $pop_hash2
#./pop -c cl3 org final $pop_hash3
#./pop -c cl1 org final $pop_hash3


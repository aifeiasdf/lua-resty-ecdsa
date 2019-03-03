require 'busted.runner'()

describe('对支持的所有算法做一次遍历，只校验正确性', function()
    it('遍历所有的算法 ', function()
        local ec = require("ecdsa")
        local t = ec.get_curves_id()
        local flag, err
        local pub, pri
        for i=1, #t, 1 do
            if t[i].nid ~= 749 and t[i].nid ~= 750 then
                local pub, pri, err = ec:generate_ec_keys(t[i].nid)
                local pub_o, _ = ec:new({public_key=pub})
                local pri_o, _ = ec:new({private_key=pri})
                local sig = pri_o:sign("hello")
                flag, _ = pub_o:verify("hello", sig)
                assert.True(flag)
            end
        end
    end)
end)


describe('用 curves nid 714 (SECG curve over a 256 bit prime field) 生成两组密钥对进行签名和验签测试', function()
    local ec = require("ecdsa")
    local pub, pri, pub2, pri2
    before_each(function()
        pub, pri = ec:generate_ec_keys(714)
        pub2, pri2 = ec:generate_ec_keys(714)
    end)
    it(' : 对hello签名和验签 预期成功 ', function()
        local pub_o, _ = ec:new({public_key=pub})
        local pri_o, _ = ec:new({private_key=pri})
        local sig = pri_o:sign("hello")
        assert.True(pub_o:verify("hello", sig))
    end)

    it(' : 对hello签名 对other验签 预期失败', function()
        local pub_o, _ = ec:new({public_key=pub})
        local pri_o, _ = ec:new({private_key=pri})
        local sig = pri_o:sign("hello")
        assert.False(pub_o:verify("other", sig))
    end)

    it(' : 用第一组私钥签名，第二组公钥验签 预期失败 ', function()
        local pri_o, _ = ec:new({private_key=pri})
        local pub2_o, _ = ec:new({public_key=pub2})
        local sig = pri_o:sign("hello")
        assert.False(pub2_o:verify("hello", sig))
    end)
end)



describe('用 curves nid 415 (X9.62 SECG curve over a 256 bit prime field) 生成两组密钥对进行签名和验签测试', function()
    local ec = require("ecdsa")
    local pub, pri, pub2, pri2
    before_each(function()
        pub, pri = ec:generate_ec_keys(415)
        pub2, pri2 = ec:generate_ec_keys(415)
    end)
    it(' : 对hello签名和验签 预期成功 ', function()
        local pub_o, _ = ec:new({public_key=pub})
        local pri_o, _ = ec:new({private_key=pri})
        local sig = pri_o:sign("hello")
        assert.True(pub_o:verify("hello", sig))
    end)

    it(' : 对hello签名 对other验签 预期失败', function()
        local pub_o, _ = ec:new({public_key=pub})
        local pri_o, _ = ec:new({private_key=pri})
        local sig = pri_o:sign("hello")
        assert.False(pub_o:verify("other", sig))
    end)

    it(' : 用第一组私钥签名，第二组公钥验签 预期失败 ', function()
        local pri_o, _ = ec:new({private_key=pri})
        local pub2_o, _ = ec:new({public_key=pub2})
        local sig = pri_o:sign("hello")
        assert.False(pub2_o:verify("hello", sig))
    end)
end)



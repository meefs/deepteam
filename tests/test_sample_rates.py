#!/usr/bin/env python3
"""
Test different sample rate values to see error messages.
"""

def test_sample_rate(value, description):
    """Test a specific sample rate value"""
    print(f"\n🧪 Testing sample_rate = {value} ({description})")
    
    try:
        from deepteam.guardrails import Guardrails
        from deepteam.guardrails.guards import PromptInjectionGuard, ToxicityGuard
        
        guardrails = Guardrails(
            input_guards=[PromptInjectionGuard()],
            output_guards=[ToxicityGuard()],
            sample_rate=value
        )
        
        print(f"✅ Sample rate {value} worked!")
        
        # Quick test to see deterministic behavior
        if value == 0.2:
            processed = 0
            for i in range(10):
                result = guardrails.guard_input(f"test {i}")
                if len(result.guard_results) > 0:
                    processed += 1
            print(f"   → Processed {processed}/10 requests (expected: {int(value * 10)})")
        
        elif value == 0.0:
            result = guardrails.guard_input("test")
            print(f"   → Guards executed: {len(result.guard_results)} (expected: 0)")
        
        elif value == 1 or value == 1.0:
            result = guardrails.guard_input("test")
            print(f"   → Guards executed: {len(result.guard_results)} (expected: >0)")
            
    except Exception as e:
        print(f"❌ Sample rate {value} failed:")
        print(f"   Error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    print("🧪 Testing Sample Rate Values")
    print("=" * 50)
    
    # Test all the requested values
    test_sample_rate(-0.2, "negative - should fail")
    test_sample_rate(0.2, "valid low - should work") 
    test_sample_rate(0.0, "zero - should work")
    test_sample_rate(1.3, "too high - should fail")
    test_sample_rate(1, "one - should work")
    
    print(f"\n🎯 Summary:")
    print("Expected results:")
    print("✅ 0.2, 0.0, 1 should work")
    print("❌ -0.2, 1.3 should fail with ValueError") 
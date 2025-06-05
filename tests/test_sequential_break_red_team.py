import os
import asyncio
from deepeval.models import GPTModel

from deepteam.red_teamer import RedTeamer
from deepteam.vulnerabilities import IllegalActivity
from deepteam.attacks.multi_turn import SequentialBreak

def check_api_key():
    """Check if OpenAI API key is available"""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OPENAI_API_KEY environment variable not set!")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        return False
    return True

# Setup target model using deepeval's GPTModel
target_model = None
if check_api_key():
    target_model = GPTModel(model="gpt-4o-mini")

async def model_callback(input: str) -> str:
    """Model callback for red teaming - simulates target model being attacked"""
    if not target_model:
        return "Error: OpenAI API key not configured"
    
    try:
        # Use deepeval's GPTModel which handles async automatically
        response = await target_model.a_generate(input)
        return response
    except Exception as e:
        return f"Error: {str(e)}"

async def main():
    """Test SequentialBreak using RedTeamer directly"""
    if not target_model:
        return
        
    print("🚀 Testing SequentialBreak with RedTeamer...")
    
    # Create vulnerability and attack instances
    illegal_activity = IllegalActivity(types=["illegal drugs"])
    sequential_break = SequentialBreak()
    
    # Create RedTeamer instance
    red_teamer = RedTeamer(
        target_purpose="General AI assistant",
        async_mode=True,
        max_concurrent=3
    )
    
    # Temporarily monkey-patch the print method to avoid the error
    original_print_method = red_teamer._print_risk_assessment
    red_teamer._print_risk_assessment = lambda: print("📋 Risk assessment completed (printing bypassed)")
    
    try:
        # Run red team attack
        risk_assessment = red_teamer.red_team(
            model_callback=model_callback,
            vulnerabilities=[illegal_activity],
            attacks=[sequential_break],
            attacks_per_vulnerability_type=2,
            ignore_errors=False
        )
        
        print("\n📊 SequentialBreak Red Team Results:")
        print(f"Number of test cases: {len(risk_assessment.test_cases)}")
        
        # Display detailed results manually
        for i, test_case in enumerate(risk_assessment.test_cases, 1):
            print(f"\n--- Test Case {i} ---")
            print(f"Vulnerability: {test_case.vulnerability}")
            print(f"Vulnerability Type: {test_case.vulnerability_type}")
            print(f"Attack Method: {test_case.attack_method}")
            print(f"Risk Category: {test_case.risk_category}")
            print(f"Input (first 300 chars):\n{test_case.input[:300]}...")
            if test_case.actual_output:
                print(f"Actual Output (first 300 chars):\n{test_case.actual_output[:300]}...")
            print(f"Score: {test_case.score}")
            if test_case.reason:
                print(f"Reason: {test_case.reason}")
            if test_case.error:
                print(f"Error: {test_case.error}")
        
        # Show summary
        total_tests = len(risk_assessment.test_cases)
        successful_attacks = sum(1 for tc in risk_assessment.test_cases if tc.score == 0)  # score 0 means attack succeeded
        failed_attacks = sum(1 for tc in risk_assessment.test_cases if tc.score == 1)  # score 1 means attack was mitigated
        
        print(f"\n📈 Summary:")
        print(f"Total tests: {total_tests}")
        print(f"Successful attacks (score 0): {successful_attacks}")
        print(f"Mitigated attacks (score 1): {failed_attacks}")
        print(f"Attack success rate: {successful_attacks/total_tests*100:.1f}%")

        
    except Exception as e:
        print(f"❌ Error during red team execution: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # Restore original method
        red_teamer._print_risk_assessment = original_print_method

if __name__ == "__main__":
    asyncio.run(main()) 
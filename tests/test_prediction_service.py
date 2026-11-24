from backend.prediction_service import predict_website


url = "https://example.com/login?user=test"

html = """
<html>
<head>
    <title>Example Login</title>
</head>
<body>
    <h1>Account Login</h1>

    <form>
        <input type="text">
        <input type="password">
        <button>Login</button>
    </form>

    <script>
        alert("Example");
    </script>
</body>
</html>
"""

result = predict_website(url, html)

print("=" * 50)
print("COMPPHISH PREDICTION SERVICE TEST")
print("=" * 50)

print("URL:", result["url"])

print("\nBranch probabilities:")

for branch, probability in result[
    "branch_probabilities"
].items():
    print(f"{branch.upper()}: {probability:.4f}")

print("\nHybrid probability:", result["hybrid_probability"])
print("Risk score:", result["risk_score"], "%")
print("Threshold:", result["threshold"])
print("Final prediction:", result["prediction"])

print("=" * 50)
print("PREDICTION SERVICE TEST COMPLETED")
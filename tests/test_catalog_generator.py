import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("catalog", ROOT / "scripts/update_aws_read_catalog.py")
catalog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalog)


class CatalogTests(unittest.TestCase):
    def test_missing_and_mutating_classification_fails_closed(self):
        self.assertIsNotNone(catalog.exclusion("service:GetData", {}))
        safe = {"Annotations": {"Properties": {name: False for name in catalog.PROPERTIES}}}
        self.assertIsNone(catalog.exclusion("service:GetData", safe))
        for field in catalog.PROPERTIES:
            changed = {"Annotations": {"Properties": dict(safe["Annotations"]["Properties"], **{field: True})}}
            self.assertIsNotNone(catalog.exclusion("service:GetData", changed))

    def test_read_labels_do_not_approve_credentials_or_execution(self):
        for operation, actions in [
            ("apigateway/GetApiKey", ["apigateway:GET"]),
            ("s3control/GetDataAccess", ["s3:GetDataAccess"]),
            ("bedrock-agent-runtime/InvokeAgent", ["bedrock:InvokeAgent"]),
            ("acm/ExportCertificate", ["acm:ExportCertificate"]),
            ("cloudformation/DetectStackDrift", ["cloudformation:DetectStackDrift"]),
            ("logs/StartQuery", ["logs:StartQuery"]),
        ]:
            self.assertIsNotNone(catalog.operation_exclusion(operation, actions), operation)
        self.assertIsNone(catalog.operation_exclusion("dynamodb/Query", ["dynamodb:Query"]))
        self.assertIsNone(catalog.operation_exclusion("personalize-runtime/GetRecommendations", ["personalize:GetRecommendations"]))


if __name__ == "__main__":
    unittest.main()

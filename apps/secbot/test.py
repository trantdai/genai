import boto3

boto3.set_stream_logger(name='boto3', level=0, format_string=None)

region = 'ap-southeast-2'

bedrockClient = boto3.client('bedrock-agent-runtime', region)

questions = "hello"

knowledgeBaseResponse  = bedrockClient.retrieve_and_generate(
    input = {'text': questions},
    retrieveAndGenerateConfiguration = {
        'knowledgeBaseConfiguration': {
            'knowledgeBaseId': '6QUSKLYVNI',
            'modelArn': f'arn:aws:bedrock:{region}::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0'
        },
        'type': 'KNOWLEDGE_BASE'
    }
)

print(knowledgeBaseResponse)




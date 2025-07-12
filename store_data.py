import json
import os
from meilisearch import Client
from meilisearch.errors import MeilisearchApiError
from tqdm import tqdm  


def load_cve_data(file_path):
    """加载每行一个JSON对象的文件"""
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:  # 跳过空行
                    try:
                        item = json.loads(line)
                        data.append(item)
                    except json.JSONDecodeError as e:
                        print(f"⚠️ 行解析失败: {line[:50]}... | 错误: {str(e)}")
        return data
    except Exception as e:
        print(f"❌ 文件读取失败: {file_path} | 错误: {str(e)}")
        return []

def setup_meilisearch_index(client, index_name="cve"):
    """配置 Meilisearch 索引（修复版）"""
    try:
        # 1. 创建索引（异步任务）
        task = client.create_index(uid=index_name, options={'primaryKey': 'cve_id'})
        
        # 2. 等待任务完成（关键步骤！）
        client.wait_for_task(task.task_uid)
        
        # 3. 获取真正的索引对象
        index = client.get_index(index_name)
        
        # 4. 配置搜索属性
        index.update_searchable_attributes([
            "cve_id", "description", "cve_mapping.explaination",
            "cve_mapping.vulnerability_type.type", "related_attcks.name"
        ])
        
        # 5. 配置筛选属性
        index.update_filterable_attributes([
            "cvss_severity", "year", "cvss_base_score",
            "cve_mapping.vulnerability_type.type"
        ])
        
        print(f"✅ 索引 {index_name} 配置完成")
        return index
    except MeilisearchApiError as e:
        print(f"❌ 索引配置失败: {e.message}")
        return None

def import_to_meilisearch(index, data, batch_size=500):
    """修复版数据导入函数"""
    try:
        total = len(data)
        for i in tqdm(range(0, total, batch_size), desc="导入进度"):
            batch = data[i:i + batch_size]
            # 提交文档并获取任务对象
            task = index.add_documents(batch)
            
            # ✅ 关键修复：等待任务完成并检查状态 [1](@ref)
            task_status = index.wait_for_task(task.task_uid)
            if task_status.status != "succeeded":
                print(f"⚠️ 批次 {i//batch_size} 提交失败: {task_status.error}")
                
        print(f"🎉 成功导入 {total} 条记录")
    except Exception as e:
        print(f"❌ 数据导入失败: {str(e)}")

if __name__ == "__main__":
    # 配置 Meilisearch 客户端
    MEILI_URL = "http://localhost:7700"
    MEILI_API_KEY = "pkucc_crimosn_data"  
    
    client = Client(MEILI_URL, MEILI_API_KEY)
    
    # 加载数据文件
    DATA_DIR = "/home/zyx/crimson_data/data/json_files"  # 替换为你的数据目录
    train_data = load_cve_data(os.path.join(DATA_DIR, "train.json"))
    test_data = load_cve_data(os.path.join(DATA_DIR, "test.json"))
    
    if not train_data and not test_data:
        print("🚫 未加载到有效数据，脚本终止")
        exit(1)
    
    # 配置索引
    index = setup_meilisearch_index(client)
    if not index:
        exit(1)
    
    # 导入数据
    if train_data:
        print(f"\n📥 开始导入训练数据 ({len(train_data)} 条)")
        import_to_meilisearch(index, train_data)
    
    if test_data:
        print(f"\n📥 开始导入测试数据 ({len(test_data)} 条)")
        import_to_meilisearch(index, test_data)
    
    # 验证结果
    try:
        stats = index.get_stats()
        print("\n🔍 导入结果统计:")
        # ✅ 使用属性访问而非下标 [6,7](@ref)
        print(f"• 总记录数: {stats.number_of_documents}")
    except MeilisearchApiError as e:
        print(f"❌ 统计获取失败: {e.message}")
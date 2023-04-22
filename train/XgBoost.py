# -*- coding: utf-8 -*-
# load module
from xgboost.sklearn import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from xgboost import plot_importance
from LoadDataset import loadDataset
from sklearn.metrics import roc_curve, auc

import matplotlib.pyplot as plt


def XGBoost():
    df = loadDataset("normal.csv", "malware1.csv")
    x_train, x_test, y_train, y_test = train_test_split(df.iloc[:, 4:-1], df.iloc[:, -1:], test_size=0.3,
                                                        random_state=42)

    # fit model for train data
    # 建立XgBoost模型
    xgb_class_model = XGBClassifier(
        learning_rate=0.1,
        n_estimators=1000,  # 树的个数--1000棵树建立xgboost
        max_depth=6,  # 树的深度
        min_child_weight=1,  # 叶子节点最小权重
        gamma=0.,  # 惩罚项中叶子结点个数前的参数
        # subsample=0.8,  # 随机选择80%样本建立决策树
        # colsample_btree=1,  # 随机选择80%特征建立决策树
        objective='binary:logitraw',  # 指定目标函数，二分类
        scale_pos_weight=1,  # 解决样本个数不平衡的问题
        random_state=27  # 随机数
    )
    # 训练模型
    # print(x_train)
    xgb_class_model.fit(x_train,
                        y_train,
                        eval_set=[(x_test, y_test)],
                        eval_metric="error",
                        early_stopping_rounds=10,
                        verbose=True
                        )

    # make prediction for test data
    y_pred = xgb_class_model.predict(x_test)
    # 这里是直接给出类型，predict_proba()函数是给出属于每个类别的概率。

    accuracy = accuracy_score(y_test, y_pred)
    print("accuarcy: %.2f%%" % (accuracy * 100.0))

    # 画图 画出俩模型的ROC曲线
    y_pred_proba = xgb_class_model.predict_proba(x_test)
    fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba[:, 1], pos_label=1)
    roc_auc_xgboost = auc(fpr, tpr)
    plt.figure()
    lw = 2
    plt.plot(fpr,tpr,color="darkorange",lw=lw,label="XgBoost_AUC=%0.4f" % roc_auc_xgboost,)
    plt.plot([0, 1], [0, 1], color="navy", lw=lw, linestyle="--")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.0])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver operating characteristic example")
    plt.legend(loc="best")
    # plt.savefig('auc_roc.pdf')
    plt.show()

    # 特征贡献度
    fig, ax = plt.subplots(figsize=(15, 15))
    plot_importance(xgb_class_model,
                    height=0.5,
                    ax=ax,
                    importance_type='gain',
                    # max_num_features=100
                    )
    plt.show()


if __name__ == "__main__":
    XGBoost()
